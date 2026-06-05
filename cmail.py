mail_password='tlbq yeki jpop iuig'
import smtplib
from email.message import EmailMessage
def send_mail(to,subject,body):
    server=smtplib.SMTP_SSL('smtp.gmail.com',465)
    server.login('danielganjayela@gmail.com','tlbq yeki jpop iuig')
    msg=EmailMessage()
    msg['From']='danielganjayela@gmail.com'
    msg['To']=to
    msg['SUBJECT']=subject
    msg.set_content(body)
    server.send_message(msg)
    print('msg sent')
    server.close()




# tlbq yeki jpop iuig