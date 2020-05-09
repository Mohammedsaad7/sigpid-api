import numpy as np
from flask import Flask,Blueprint, request, jsonify, render_template,flash, redirect, url_for, session, logging
import pickle
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
import os
import pandas as pd
import numpy as np

app=Flask(__name__)
UPLOAD_URL='http://192.168.1.103:5000/static/'
model=pickle.load(open('rfc_sig.pkl','rb'))


def sigpidclass(path):
    # import pandas as pd
    # app.config['SFILE']=r"C:\Users\moham\drebinsayo\scripts\srd"
    # ds=app.config["SFILE"]
    # ps=os.listdir(ds)
    # for fffs in ps:
    #     bbbs=os.path.join(app.config["SFILE"], fffs)
    #     os.remove(bbbs)
    # files = request.files["file"]
    # apple=app.config['SFILE']
    # files.save(os.path.join(app.config["SFILE"], files.filename))
    # # import GetApkData as ge
    # # import importlib
    # # importlib.reload(ge)
    # sapple=files.filename
    # fsapple=ds+"\\"+sapple
    from androguard.misc import AnalyzeAPK
    a,d,dx=AnalyzeAPK(path)
    ttapp=a.get_permissions()
    #ttapp= android.permission.send_sms
    for t in ttapp:
        if t[0]!='a':
            ttapp.remove(t)
    el=[]
    for i in ttapp:
        k=i.split('.')[-1]
        el.append(k)
    dpermf=pd.read_csv('onlydangsigt.csv')
    malapp={i: 0 for i in dpermf.columns}
    del malapp['malware']
    for i in el:
        for j in malapp:
            if(i==j):
                malapp[j]=1
    y_testap=list(malapp.values())
    y_testwork=np.array([np.array(y_testap)])
    model=pickle.load(open('rfc_sig.pkl', 'rb'))
    bans=model.predict(y_testwork)
    if (bans==False):
        band="benign"
    else:
        band="malware"
    return band

@app.route('/')
def home():
    return render_template('filesigpid.html')

@app.route('/predict' ,methods=['POST'])
def predict():
    if request.method == 'POST':
    # check if the post request has the file part
        if 'file' not in request.files:
           return "someting went wrong 1"
      
        user_file = request.files['file']
        temp = request.files['file']
        if user_file.filename == '':
            return "file name not found ..." 


        else:
            path=os.path.join(os.getcwd()+'\\static\\'+user_file.filename)
            user_file.save(path)
            result=sigpidclass(path)
            return jsonify(result)



if __name__ == "__main__":
    app.run(debug=True)