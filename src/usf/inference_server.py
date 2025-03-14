
import struct
import time
import fastapi
from trainer import Args
import uvicorn
from fastapi import FastAPI, Request, Response, status, Form, HTTPException, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from aiohttp import ClientSession

from preprocess_flow_stats import NormalizeSolution
import pandas as pd
import pickle
import torch
import numpy as np
import os
from models import DPIModel, all_android_domains
from trainer import collate_fn

from contextlib import asynccontextmanager

TMP_DIR = '/nvme0/domainwatcher_tmp'
app = fastapi.FastAPI()

def create_dpi_model(args: Args) :
    model = DPIModel(65, num_category_inputs = 2, num_cat_per_category_input = 16, dpi_bytes = args.dpi_n_dpi_bytes)
    model = model.cuda()
    model.eval()
    return model

MODEL_DPI = None
NORAMLIZE_SOLUTION = None

class UeRequest(BaseModel):
    ue_ip: str

@app.post('/add_monitored_ue') # given an UE IP, add it to the list of monitored UEs
async def add_monitored_ue(req: UeRequest):
    # call POST 127.0.0.1:5185/add_ue with ue_ip
    async with ClientSession() as session:
        async with session.post('http://127.0.0.1:5185/add_ue', json={'ue_ip': req.ue_ip}) as response:
            return response.status


@app.post("/upload_model") # upload a preprocessing pkl file and a checkpoint pth file
async def upload_model(
    request: Request,
    preprocessing_pkl: UploadFile = File(None),
    checkpoint_pth: UploadFile = File(None),
):
    # save to TMP_DIR
    if preprocessing_pkl:
        with open(f'{TMP_DIR}/normalize_solution.pkl', 'wb') as f:
            f.write(preprocessing_pkl.file.read())
    global NORAMLIZE_SOLUTION
    NORAMLIZE_SOLUTION = pickle.load(open(f'{TMP_DIR}/normalize_solution.pkl', 'rb'))
    if checkpoint_pth:
        with open(f'{TMP_DIR}/model.pth', 'wb') as f:
            f.write(checkpoint_pth.file.read())
    global MODEL_DPI
    MODEL_DPI = create_dpi_model(Args())
    MODEL_DPI.load_state_dict(torch.load(f'{TMP_DIR}/model.pth'))
    return {"status": "success"}

dpi_max_flows = 4000
flow_dropout_ratio = 0.0
dpi_n_dpi_bytes = 160
category_columns = ['Feat 0', 'Feat 1']

def decode_features_and_preprocess(features_binary: bytes) -> torch.Tensor :
    pd_columns = ['Flow ID', 'Host', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Timestamp', 'Content', 'DNS Query', 'DNS Resp']
    for i in range(0, 65 + 2) :
        pd_columns.append(f'Feat {i}')
    # create dataframe
    df = pd.DataFrame(columns=pd_columns)
    offset = 0
    # read first 4 bytes big-endian to get the number of flows
    n_flows = int.from_bytes(features_binary[:4], byteorder='big'); offset += 4
    for i in range(n_flows) :
        # read has_dns
        has_dns = features_binary[offset] != 0; offset += 1
        # read client_ip
        client_ip = int.from_bytes(features_binary[offset:offset+4], byteorder='big'); offset += 4
        # read client_port
        client_port = int.from_bytes(features_binary[offset:offset+2], byteorder='big'); offset += 2
        # read server_ip
        server_ip = int.from_bytes(features_binary[offset:offset+4], byteorder='big'); offset += 4
        # read server_port
        server_port = int.from_bytes(features_binary[offset:offset+2], byteorder='big'); offset += 2
        # read first_pkt_ts, microseconds from 1970 UTC
        first_pkt_ts = int.from_bytes(features_binary[offset:offset+8], byteorder='big'); offset += 8
        # read 2 int features
        feat_int = [0, 0]
        for j in range(2) :
            feat_int[j] = int.from_bytes(features_binary[offset:offset+4], byteorder='big'); offset += 4
        # read 65 float features
        feat_fp = [0.0 for _ in range(65)]
        for j in range(65) :
            feat_fp[j] = struct.unpack('>d', features_binary[offset:offset+8])[0]; offset += 8
        # read DPI content
        content_len = dpi_n_dpi_bytes
        dpi_bytes_len = int.from_bytes(features_binary[offset:offset+4], byteorder='big'); offset += 4
        content = features_binary[offset:offset+content_len]; offset += content_len
        # read DNS query
        dns_query = None
        if has_dns :
            query_len = int.from_bytes(features_binary[offset:offset+4], byteorder='big'); offset += 4
            dns_query = features_binary[offset:offset+query_len].decode('utf-8'); offset += query_len
        else :
            dns_query = 'N/A'
        first_pkt_ts = pd.Timestamp(first_pkt_ts, unit='us')
        # convert to pandas row
        row = [
            i, # Flow ID
            None, # Host
            client_ip, # Src IP
            client_port, # Src Port
            server_ip, # Dst IP
            server_port, # Dst Port
            first_pkt_ts, # Timestamp
            content[:dpi_bytes_len].hex(), # Content
            dns_query, # DNS Query
            'N/A', # DNS Resp
        ]
        for i in range(2) :
            row.append(feat_int[i])
        for i in range(65) :
            row.append(feat_fp[i])
        # append to dataframe
        df.loc[len(df)] = row
    # preprocess
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce', format='ISO8601')
    df = df.dropna(subset = ['Timestamp'])  # Drop rows with NaT values
    df['Start TS'] = (df['Timestamp'] - df['Timestamp'].min()).dt.total_seconds()
    df['End TS'] = df['Start TS'] + df['Feat 2']
    df = df.drop(['Flow ID', 'Src IP','Src Port','Dst IP','Dst Port','Timestamp', 'DNS Resp'], axis=1)
    df = df.fillna(0)
    n_bytes = 0
    n = df.shape[0]
    if df.shape[0] > dpi_max_flows :
        drop_indices = np.random.choice(df.index, df.shape[0] - dpi_max_flows, replace = False)
        df = df.drop(drop_indices)
    n_bytes += int(df['Feat 3'].sum())
    dpi_bytes = [bytearray.fromhex(h)[: dpi_n_dpi_bytes] for h in df['Content']]
    dpi_bytes = [h + b'\00' * (dpi_n_dpi_bytes - len(h)) for h in dpi_bytes]
    dpi_bytes = [np.array(h, dtype = np.uint8) for h in dpi_bytes]
    dpi_bytes = np.stack(dpi_bytes, axis = 0)
    col_start_ts = np.array(df['Start TS']).astype(np.int64)
    col_end_ts = np.array(df['End TS']).astype(np.int64)

    ip_counts = df['Host'].value_counts().reset_index()
    ip_counts.columns = ['Host', 'count']
    sorted_ips = ip_counts.sort_values(by='count', ascending=False)

    # Assign IDs
    if len(sorted_ips) > 500:
        sorted_ips['id'] = np.arange(1, 501).tolist() + [0] * (len(sorted_ips) - 500)
    else:
        sorted_ips['id'] = np.arange(1, len(sorted_ips) + 1)

    # Ensure each IP gets a unique ID
    unique_ids = np.random.permutation(sorted_ips['id'].unique())
    id_map = dict(zip(sorted_ips['id'].unique(), unique_ids))
    sorted_ips['id'] = sorted_ips['id'].apply(lambda x: id_map[x])
    df = df.merge(sorted_ips[['Host', 'id']], on='Host', how='left')
    host_ids = df['id']

    df = df.drop(['Content', 'Start TS', 'End TS', 'Host', 'id', 'DNS Query'], axis = 1)
    if NORAMLIZE_SOLUTION is not None :
        for col in df.columns :
            df[col] = NORAMLIZE_SOLUTION[col].apply(df[col])
    cat_cols = np.stack([df[col].to_numpy() for col in category_columns], axis = -1)
    label = 1
    df_clean = df.drop(category_columns, axis = 1)
    df_clean = df_clean.to_numpy()
    host_ids = host_ids.to_numpy()
    return df_clean, cat_cols, col_start_ts, col_end_ts, dpi_bytes, host_ids, label, n, n_bytes

@app.get('/predict_ue') # gievn an UE IP, predict the score
async def predict_ue(req: UeRequest):
    global MODEL_DPI, NORAMLIZE_SOLUTION
    if MODEL_DPI is None or NORAMLIZE_SOLUTION is None:
        return {"status": "model not loaded yet"}
    t0 = time.perf_counter()
    # retrieve features
    async with ClientSession() as session:
        async with session.post('http://127.0.0.1:5185/get_ue_stats', json={'ue_ip': req.ue_ip}) as response:
            # check if the response is successful
            if response.status != 200:
                return {"status": "error"}
            # get features as binary blob
            features_binary = response.content
    t1 = time.perf_counter()
    t_features = t1 - t0
    features = decode_features_and_preprocess(features_binary)
    dpi_x, dpi_xc, dpi_x_start_ts, dpi_x_end_ts, dpi_x_dpi_bytes, dpi_x_host_ids, dpi_mask, label, n_flows2, n_bytes = collate_fn([features])
    t0 = time.perf_counter()
    with torch.no_grad() :
        score_dpi = MODEL_DPI(
            dpi_x.cuda(),
            dpi_xc.cuda(),
            dpi_x_start_ts,
            dpi_x_end_ts,
            dpi_x_dpi_bytes.cuda(),
            dpi_x_host_ids.cuda(),
            dpi_mask.cuda()
        ).softmax(dim = 1)[:, 1]
        score_dpi = score_dpi.cpu().item()
    t1 = time.perf_counter()
    t_inference = t1 - t0
    return {"score": score_dpi, "t_features": t_features, "t_inference": t_inference}
    
