#!/bin/bash
mkdir -p /home/intsec/models/multiclass_v1
cd /home/intsec/models/multiclass_v1
wget -q http://192.168.1.16:8888/multiclass_v1/model.joblib
wget -q http://192.168.1.16:8888/multiclass_v1/scaler.joblib
wget -q http://192.168.1.16:8888/multiclass_v1/feature_names.json
wget -q http://192.168.1.16:8888/multiclass_v1/metadata.json
echo "Dosyalar indirildi:"
ls -lh /home/intsec/models/multiclass_v1/
