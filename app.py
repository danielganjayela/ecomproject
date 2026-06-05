from flask import Flask,request,redirect,url_for,jsonify,session
from flask_session import Session #security layer
from flask_bcrypt import Bcrypt
import re
from otp import genotp
from cmail import send_mail
from stoken import endata,dndata
from mysql.connector import (connection)
from datetime import timedelta
import uuid
from werkzeug.utils import secure_filename #used to check secured filenames
import os
mydb=connection.MySQLConnection(user='root',host='localhost',password='Daniel@666',db='ecommerce27db')
app=Flask(__name__)
app.permanent_session_lifetime=timedelta(days=1)
app.secret_keys='Code123'
app.config['SESSION_TYPE']='filesystem'
app.config['SESSION_COOKIE_SECURE']=True
app.config['SESSION_COOKIE_HTTPONLY']=True
app.config['SESSIO_COOKIE_SAMESITE']='None'
Session(app)
#upload folder creation in static dynamically
BASE_DIR=os.path.abspath(os.path.dirname(__file__))  #return app directory path
print(BASE_DIR)
UPLOAD_FOLDER=os.path.join(BASE_DIR,'static','uploads')
os.makedirs(UPLOAD_FOLDER,exist_ok=True)
ALLOWED_EXTENSIONS={"png","jpeg","jpg","gif","webp","jfif"}
MAX_CONTENT_LENGTH=6*1024*1024  #6mb
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER
bcrypt=Bcrypt(app)
@app.route('/api/admin/register',methods=['POST'])
def admincreate():
    try:
        data=request.get_json()
        print(data)
        if not data:
            return jsonify({'Status':'failed','message':'No input data'}),400
        admin_name=data.get('username','').strip()
        admin_email=data.get('useremail','').strip()
        admin_password=data.get('userpassword','').strip()
        admin_adress=data.get('useradress','').strip()
        admin_phone=data.get('userphone','').strip()
        admin_agree=data.get('useragree')
        #validation
        if not admin_name:
            return jsonify({'status':'failed','message':'Username requires'}),400
        email_pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern,admin_email):
            return jsonify({'status':'failed','message':'Invalid email'}),400
        try:
            mydb.ping(reconnect=True)
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from admindata where admin_useremail=%s',[admin_email,])
            email_exists=cursor.fetchone()[0]
            if email_exists>0:
                return jsonify({'status':'failed','message':'Email already registered'}),400
        except Exception as e:
            print("Mysql Error",str(e))
            return jsonify({'status':'failed','message':str(e)}),500
        if len(admin_password)<6:
            return jsonify({'status':'failed','message':'Password Too Short'}),400
        #hash value for password encryption
        hashed_password=bcrypt.generate_password_hash(admin_password).decode('utf-8')
        gotp=genotp()
        admindata={'admin_username':admin_name,'admin_useremail':admin_email,'admin_userpassword':hashed_password,'admin_address':admin_adress,'admin_agree':admin_agree,'admin_phoneno':admin_phone,'admin_otp':gotp}
        subject='Admin Registration Verification'
        body=f''' Hello Admin, 
                       Your OTP is:{gotp}  
                       This OTP is valid for 5 minutes.  
                       BUYROUTE Team'''
        send_mail(to=admin_email,subject=subject,body=body)
        token=endata(admindata)
        return jsonify({'status':'success','message':'OTP Sent Successfully','token':token}),200
    except Exception as e:
        print ('Error occurs:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
@app.route('/api/admin/verify-otp', methods=['POST'])  
def adminotpverify():
    try:
        data=request.get_json()
        print(data)
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        userotp=data.get('otp')
        token=data.get('token')
        if not userotp or not token:
            return jsonify({'status':'failed','message':'OTP and Token are required'}),400
        #decrypt token safely
        try:
            admin_details=dndata(token)
        except Exception as e:
            return jsonify({'status':'failed','message':'Invalid or expired token'}),400
        #otp verification
        if str(userotp)!=str(admin_details['admin_otp']):
            return jsonify({'status':'failed','message':'Invalid OTP'}),400
        #reconnect automatically if mysql connection lost
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select count(*) from admindata where admin_useremail=%s',[admin_details['admin_useremail'],])
        email_exists=cursor.fetchone()[0]
        if email_exists:
            return jsonify({'status':'failed','message':'Email already registered'}),400
        cursor.execute('insert into admindata (adminid ,admin_username,admin_useremail,admin_address,admin_password,admin_phoneno,admin_agree) values (uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s)',(admin_details['admin_username'],admin_details['admin_useremail'],admin_details['admin_address'],admin_details['admin_userpassword'],admin_details['admin_phoneno'],admin_details['admin_agree']))
        mydb.commit()
        return jsonify({'status':'success','message':'Admin registered successfully'}),200
    except Exception as e:
        mydb.rollback()#undo the transaction
        print("Mysql Error",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
@app.route('/api/admin/login',methods=['POST'])
def adminlogin():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'NO Input Data'}),400
        login_email=data.get('email','').strip()
        login_password=data.get('password','').strip()
        if not login_email or not login_password:
            return jsonify({'status':'failed','message':'Email and Password required'}),400
        #reconnect automatically if mysql connection lost
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(adminid),admin_username,admin_useremail,admin_password from admindata where admin_useremail=%s',[login_email])
        admin_data=cursor.fetchone()
        if not admin_data:
            return jsonify({'status':'failed','message':'Invalid email'}),400
        adminid=admin_data[0]
        adminname=admin_data[1]
        adminemail=admin_data[2]
        stored_password=admin_data[3]
        if not bcrypt.check_password_hash(stored_password,login_password):
            return jsonify({'status':'failed','message':'Invalid Password'}),401
        session['adminid']=adminid
        session['adminemail']=adminemail
        return jsonify({'status':'success','message':'Login Successful','admin':{'adminid':adminid,'adminname':adminname,'adminemail':adminemail}}),500
    except Exception as e:
        print ('Mysql Error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),200
    finally:
        if cursor:
            cursor.close()
@app.route('/api/admin/dashboard',methods=['GET'])
def admindashboard():
    try:
        #session validation
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'please login first'}),401
        return jsonify({'status':'success','message':'Welcome to Admin Dashboard',
        'admin':{'adminid':session.get('adminid'),'adminemail':session.get('adminemail')}}),200
    except Exception as e:
        print('Error occurs:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
def allowed_file(filename:str)->bool:
    return ('.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS)

@app.route('/api/admin/add-item',methods=['POST'])    
def additem():
    save_path=None
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'please login first'}),401
        item_name=request.form.get('title','').strip()
        item_description=request.form.get('Description','').strip()
        item_about=request.form.get('About_item','').strip()
        item_quantity=request.form.get('quantity','').strip()
        item_price=request.form.get('price','').strip()
        item_category=request.form.get('category','').strip()
        #form validation
        if not item_name:
            return jsonify({'status':'failed','message':'Item name is required'}),400
        try:
            item_price=float(item_price)
            item_quantity=int(item_quantity)
        except ValueError:
            return jsonify({'status':'failed','message':'Invalid price or quantity'}),400
        item_filedata=request.files.get('file')
        if not item_filedata:
            return jsonify({'status':'failed','message':'Item image is required'}),400
        filename=item_filedata.filename
        if not allowed_file(filename):
            return jsonify({'status':'failed','message':'Invalid file type'}),400
        if not item_filedata.mimetype.startswith('image/'):
            return jsonify({'status':'failed','message':'Invalid image'}),400
        orig_secure=secure_filename(filename) #removes extra / spaces
        ext=os.path.splitext(orig_secure)[1] #returns file extension
        filename=genotp()+ext #generates unique file name using otp
        save_path=os.path.join(app.config['UPLOAD_FOLDER'],filename) 
        item_filedata.save(save_path) #stores image  in savepath
        # reconnect automatically if mysql connection is lost
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''insert into items(itemid,item_name,item_description,item_about,quantity,price,category,item_filename,added_by)
        values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s,%s,uuid_to_bin(%s))''',
        [item_name,item_description,item_about,item_quantity,item_price,item_category,filename,adminid])
        mydb.commit()
        return jsonify({'status':'success','message':'Item added successfully','image':url_for('static', filename=f'uploads/{filename}',_external=True)}),200    
    except Exception as e:
        mydb.rollback()
        print('ADD ITEM Error:',str(e))
        if save_path and os.path.exists(save_path):
            os.remove(save_path) #removes file if error occurs after saving
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/items',methods=['GET'])            
def viewallitems():
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'please login first'}),401
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,
        item_filename,created_at from items where added_by=uuid_to_bin(%s)''',[adminid])
        allitems_data=cursor.fetchall()
        products=[]
        for item in allitems_data:
            products.append({'itemid':item[0],
                             'itemname':item[1],
                             'item_desc':item[2],
                             'item_about':item[3],
                             'price':float(item[4]),
                             'quantity':item[5],
                             'category':item[6],
                             'image':url_for('static', filename=f'uploads/{item[7]}',_external=True),})
        return jsonify({'status':'success','products':products}),200
    except Exception as e:
        print('VIEW ITEMS Error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/item/<itemid>',methods=['GET'])
def viewitem(itemid):
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'please login first'}),401
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({'status':'failed','message':'Invalid item ID'}),400
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,
        item_filename,created_at from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)''',[adminid,itemid])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({'status':'failed','message':'Item not found'}),404
        products={'itemid':item_data[0],
                  'itemname':item_data[1],
                  'item_desc':item_data[2],
                  'item_about':item_data[3],
                  'price':float(item_data[4]),
                  'quantity':item_data[5],
                  'category':item_data[6],
                  'image':url_for('static', filename=f'uploads/{item_data[7]}',_external=True),}
        return jsonify({'status':'success','products':products}),200
    except Exception as e:
        print('VIEW ITEMS Error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()   

@app.route('/api/admin/delete-item/<itemid>',methods=['DELETE'])
def deleteitem(itemid):
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'please login first'}),401
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({'status':'failed','message':'Invalid item ID'}),400
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,
        item_filename,created_at from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)''',[adminid,itemid])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({'status':'failed','message':'Item not found'}),404
        image_name=item_data[7]
        remove_path=os.path.join(app.config['UPLOAD_FOLDER'],image_name)
        #delete item in DB
        cursor.execute('''delete from items where itemid=uuid_to_bin(%s) and added_by=uuid_to_bin(%s)''',[itemid,adminid])
        mydb.commit()
        #delete image in static folder
        if os.path.exists(remove_path):
            os.remove(remove_path)        
        return jsonify({'status':'success','message':'Item deleted successfully'}),200
    except Exception as e:
        mydb.rollback()#undo the transaction
        print('DELETE ITEM ERROR',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()

if __name__=='__main__':
    app.run()