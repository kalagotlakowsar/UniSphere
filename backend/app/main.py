from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Form
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import base64, json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import os, hashlib, hmac, secrets, csv, io

ROOT=Path(__file__).resolve().parents[2]; DATA=ROOT/'data'; UPLOADS=DATA/'uploads'; DATA.mkdir(exist_ok=True); UPLOADS.mkdir(exist_ok=True)
URL=os.getenv('DATABASE_URL',f"sqlite:///{(DATA/'unisphere.db').as_posix()}")
if URL.startswith('postgres://'): URL=URL.replace('postgres://','postgresql+psycopg://',1)
elif URL.startswith('postgresql://'): URL=URL.replace('postgresql://','postgresql+psycopg://',1)
engine=create_engine(URL,connect_args={'check_same_thread':False} if URL.startswith('sqlite') else {},pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False); Base=declarative_base()
SECRET=os.getenv('UNISPHERE_SECRET','dev-secret-change-before-deploy'); ADMIN_ID=os.getenv('UNISPHERE_ADMIN_ID','admin'); ADMIN_PASSWORD=os.getenv('UNISPHERE_ADMIN_PASSWORD','Hope@50')
def hashpw(p):
    salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,260000); return salt.hex()+':'+digest.hex()
def checkpw(p,h):
    try:
        salt,digest=h.split(':'); return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(salt),260000).hex(),digest)
    except Exception:return False
class User(Base):
    __tablename__='users'; id=Column(Integer,primary_key=True); login=Column(String(80),unique=True,index=True); password=Column(String(200)); role=Column(String(20)); active=Column(Boolean,default=True)
class Student(Base):
    __tablename__='students'; id=Column(Integer,primary_key=True); sid=Column(String(40),unique=True,index=True); name=Column(String(120)); department=Column(String(80),default='CSE'); year=Column(Integer,default=3); section=Column(String(10),default='A'); email=Column(String(120),default=''); phone=Column(String(30),default=''); tenth=Column(Float,default=90); twelfth=Column(Float,default=90); cgpa=Column(Float,default=8); attendance=Column(Float,default=80); marks=Column(Float,default=60); backlogs=Column(Integer,default=0); lms=Column(Float,default=70); engagement=Column(Float,default=60); skills=Column(Float,default=60); coding=Column(Float,default=60); aptitude=Column(Float,default=60); mock=Column(Float,default=60); placement=Column(Float,default=60); assignments=Column(Float,default=70); active=Column(Boolean,default=True)
class Mark(Base):
    __tablename__='marks'; id=Column(Integer,primary_key=True); sid=Column(String(40),index=True); subject=Column(String(100)); assessment=Column(String(100)); score=Column(Float); maximum=Column(Float); created=Column(DateTime,default=datetime.utcnow)
class Attendance(Base):
    __tablename__='attendance'; id=Column(Integer,primary_key=True); sid=Column(String(40),index=True); subject=Column(String(100)); day=Column(String(20)); status=Column(String(20)); created=Column(DateTime,default=datetime.utcnow)
class Message(Base):
    __tablename__='messages'; id=Column(Integer,primary_key=True); sid=Column(String(40),index=True); sender=Column(String(80)); subject=Column(String(180)); body=Column(Text); kind=Column(String(30),default='message'); reply=Column(Text,default=''); created=Column(DateTime,default=datetime.utcnow)
class Intervention(Base):
    __tablename__='interventions'; id=Column(Integer,primary_key=True); sid=Column(String(40),index=True); title=Column(String(180)); action=Column(Text); due=Column(String(20),default=''); status=Column(String(30),default='pending'); remarks=Column(Text,default=''); created=Column(DateTime,default=datetime.utcnow)
class Resource(Base):
    __tablename__='resources'; id=Column(Integer,primary_key=True); title=Column(String(180)); subject=Column(String(100)); filename=Column(String(255)); stored=Column(String(255)); uploader=Column(String(80)); created=Column(DateTime,default=datetime.utcnow)
class Feedback(Base):
    __tablename__='feedback'; id=Column(Integer,primary_key=True); sid=Column(String(40)); faculty=Column(String(120)); body=Column(Text); created=Column(DateTime,default=datetime.utcnow)
class Audit(Base):
    __tablename__='audit'; id=Column(Integer,primary_key=True); actor=Column(String(80)); action=Column(String(120)); detail=Column(Text,default=''); created=Column(DateTime,default=datetime.utcnow)
Base.metadata.create_all(engine)
def getdb():
    db=SessionLocal()
    try: yield db
    finally: db.close()
def _b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def token(login,role):
    header=_b64(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode()); payload=_b64(json.dumps({'sub':login,'role':role,'exp':int((datetime.utcnow()+timedelta(hours=10)).timestamp())},separators=(',',':')).encode()); sig=_b64(hmac.new(SECRET.encode(),f'{header}.{payload}'.encode(),hashlib.sha256).digest()); return f'{header}.{payload}.{sig}'
def decode_token(value):
    try:
        a,b,c=value.split('.'); expected=_b64(hmac.new(SECRET.encode(),f'{a}.{b}'.encode(),hashlib.sha256).digest())
        if not hmac.compare_digest(c,expected): raise ValueError()
        payload=json.loads(base64.urlsafe_b64decode(b+'='*((4-len(b)%4)%4)))
        if payload.get('exp',0)<int(datetime.utcnow().timestamp()): raise ValueError()
        return payload
    except Exception: raise ValueError('Invalid or expired token')
def userdep(authorization:Optional[str]=Header(None),db:Session=Depends(getdb)):
    if not authorization or not authorization.startswith('Bearer '):raise HTTPException(401,'Please sign in.')
    try:p=decode_token(authorization[7:])
    except ValueError:raise HTTPException(401,'Session expired.')
    u=db.query(User).filter_by(login=p.get('sub'),active=True).first()
    if not u or u.role!=p.get('role'):raise HTTPException(401,'Account unavailable.')
    return {'login':u.login,'role':u.role}
def allow(*roles):
    def dep(u=Depends(userdep)):
        if u['role'] not in roles:raise HTTPException(403,'Insufficient permissions.')
        return u
    return dep
def score(s):return round(.30*s.cgpa*10+.20*s.attendance+.15*(.65*s.lms+.35*s.assignments)+.10*s.engagement+.10*s.skills+.15*s.placement,1)
def student_json(s):
    sc=score(s); reasons=[]
    if s.attendance<75:reasons.append(f'Attendance is {s.attendance:.0f}%, below 75%.')
    if s.marks<50:reasons.append(f'Internal marks are {s.marks:.0f}/100.')
    if s.backlogs>=2:reasons.append(f'{s.backlogs} active backlogs need follow-up.')
    if s.assignments<60:reasons.append(f'Assignment completion is {s.assignments:.0f}%.')
    if s.placement<50:reasons.append(f'Placement readiness is {s.placement:.0f}/100.')
    risk='High' if sc<50 or s.attendance<55 or s.marks<35 or s.backlogs>=3 else ('Medium' if sc<70 or s.attendance<75 or s.marks<50 or s.backlogs else 'Low')
    if not reasons:reasons=['No critical indicators crossed the current monitoring thresholds.']
    return {'sid':s.sid,'name':s.name,'department':s.department,'year':s.year,'section':s.section,'email':s.email,'phone':s.phone,'tenth':s.tenth,'twelfth':s.twelfth,'cgpa':s.cgpa,'attendance':s.attendance,'marks':s.marks,'backlogs':s.backlogs,'lms':s.lms,'engagement':s.engagement,'skills':s.skills,'coding':s.coding,'aptitude':s.aptitude,'mock':s.mock,'placement':s.placement,'assignments':s.assignments,'score':sc,'risk':risk,'reasons':reasons,'academic_risk':'High' if s.attendance<65 or s.marks<40 or s.backlogs>=3 else 'Medium' if s.attendance<75 or s.marks<55 or s.backlogs else 'Low','placement_risk':'High' if s.placement<45 else 'Medium' if s.placement<65 else 'Low'}
def audit(db,u,a,d=''):db.add(Audit(actor=u,action=a,detail=d));db.commit()
def seed():
 db=SessionLocal()
 try:
  if not db.query(User).filter_by(login=ADMIN_ID).first():db.add(User(login=ADMIN_ID,password=hashpw(ADMIN_PASSWORD),role='admin'))
  demos=[('faculty01','Faculty@123','faculty'),('faculty02','Faculty@123','faculty')]+[(f'STU100{i}','Student@123','student') for i in range(1,7)]
  for login,pw,role in demos:
   if not db.query(User).filter_by(login=login).first():db.add(User(login=login,password=hashpw(pw),role=role))
  db.commit()
  rows=[('STU1001','Aarav Reddy','CSE',8.8,92,82,0,90,78,88,86),('STU1002','Mira Sharma','CSE',7.1,62,43,2,54,45,51,42),('STU1003','Ishaan Kumar','CSE',9.1,68,78,0,85,60,58,38),('STU1004','Ananya Rao','IT',8.0,81,68,1,76,66,73,70),('STU1005','Kabir Das','ECE',6.4,57,36,3,42,30,40,34),('STU1006','Zoya Khan','CSE',8.6,88,75,0,83,91,81,90)]
  for i,r in enumerate(rows):
   sid,name,dept,cgpa,att,marks,back,lms,eng,skills,placement=r
   if not db.query(Student).filter_by(sid=sid).first():db.add(Student(sid=sid,name=name,department=dept,cgpa=cgpa,attendance=att,marks=marks,backlogs=back,lms=lms,engagement=eng,skills=skills,placement=placement,coding=skills-4,aptitude=skills+2,mock=skills,assignments=max(25,lms-5),tenth=89+i,twelfth=91+i%5,email=f'{sid.lower()}@demo.unisphere.edu',phone=f'900000000{i+1}'))
  db.commit()
  if not db.query(Message).count():db.add(Message(sid='STU1002',sender='faculty01',subject='Attendance follow-up',body='Your attendance is below the monitoring threshold. Please share context and meet during office hours.',kind='question'));db.add(Message(sid='STU1005',sender='faculty02',subject='Remedial work',body='Please complete the Data Structures practice set by Friday.',kind='assignment'));db.commit()
 finally:db.close()
seed()
app=FastAPI(title='UniSphere API',version='1.0.0')
@app.get('/api/health')
def health():return {'status':'ok','service':'UniSphere','database':'connected'}
@app.post('/api/auth/login')
def login(data:dict,db:Session=Depends(getdb)):
 role=data.get('role');login=data.get('login_id','').strip();u=db.query(User).filter_by(login=login,role=role,active=True).first()
 if not u or not checkpw(data.get('password',''),u.password):raise HTTPException(401,'Invalid ID or password.')
 audit(db,login,'login',role);return {'access_token':token(login,role),'role':role,'login_id':login}
@app.get('/api/me')
def me(u=Depends(userdep)):return u
@app.get('/api/students')
def students(q:str='',risk:str='',department:str='',u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 arr=[student_json(s) for s in db.query(Student).filter(Student.active==True).all()]
 if q:arr=[s for s in arr if q.lower() in s['name'].lower() or q.lower() in s['sid'].lower()]
 if risk:arr=[s for s in arr if s['risk'].lower()==risk.lower()]
 if department:arr=[s for s in arr if s['department']==department]
 return arr
@app.get('/api/students/me')
def my_student(u=Depends(allow('student')),db:Session=Depends(getdb)):
 s=db.query(Student).filter_by(sid=u['login']).first()
 if not s:raise HTTPException(404,'Student profile missing.')
 return student_json(s)
@app.get('/api/students/{sid}')
def one_student(sid:str,u=Depends(userdep),db:Session=Depends(getdb)):
 if u['role']=='student' and u['login']!=sid:raise HTTPException(403,'You can only view your own profile.')
 s=db.query(Student).filter_by(sid=sid).first()
 if not s:raise HTTPException(404,'Student not found.')
 return student_json(s)
@app.post('/api/admin/users')
def create_user(data:dict,u=Depends(allow('admin')),db:Session=Depends(getdb)):
 role=data.get('role');login=data.get('login_id','').strip();pw=data.get('password','')
 if role not in ('student','faculty') or len(pw)<8 or not login:raise HTTPException(400,'Use a student/faculty role, ID, and password of at least 8 characters.')
 if db.query(User).filter_by(login=login).first():raise HTTPException(409,'Login ID already exists.')
 db.add(User(login=login,password=hashpw(pw),role=role))
 if role=='student':db.add(Student(sid=login,name=data.get('name') or login,department=data.get('department','CSE'),year=int(data.get('year',3)),section=data.get('section','A'),email=data.get('email',''),phone=data.get('phone','')))
 db.commit();audit(db,u['login'],'user_created',login);return {'message':'Account created.'}
@app.patch('/api/students/{sid}')
def update_student(sid:str,data:dict,u=Depends(allow('admin','faculty')),db:Session=Depends(getdb)):
 s=db.query(Student).filter_by(sid=sid).first()
 if not s:raise HTTPException(404,'Student not found.')
 fields={'name':str,'department':str,'year':int,'section':str,'cgpa':float,'attendance':float,'marks':float,'backlogs':int,'lms':float,'engagement':float,'skills':float,'placement':float,'assignments':float}
 for k,v in data.items():
  if k in fields:
   try: v=fields[k](v)
   except:raise HTTPException(400,f'Invalid {k}.')
   if k in ('cgpa',) and not 0<=v<=10:raise HTTPException(400,'CGPA must be 0–10.')
   if k in ('attendance','marks','lms','engagement','skills','placement','assignments') and not 0<=v<=100:raise HTTPException(400,f'{k} must be 0–100.')
   setattr(s,k,v)
 db.commit();audit(db,u['login'],'student_updated',sid);return student_json(s)
@app.get('/api/analytics/overview')
def overview(u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 ss=[student_json(s) for s in db.query(Student).filter_by(active=True).all()];n=len(ss) or 1;depts={}
 for s in ss:
  d=depts.setdefault(s['department'],{'department':s['department'],'count':0,'cgpa':0,'attendance':0,'high':0,'placement':0});d['count']+=1;d['cgpa']+=s['cgpa'];d['attendance']+=s['attendance'];d['high']+=s['risk']=='High';d['placement']+=s['placement']
 for d in depts.values():
  k=d['count'];d['cgpa']=round(d['cgpa']/k,2);d['attendance']=round(d['attendance']/k,1);d['placement']=round(d['placement']/k,1)
 return {'total_students':len(ss),'total_faculty':db.query(User).filter_by(role='faculty',active=True).count(),'avg_cgpa':round(sum(s['cgpa'] for s in ss)/n,2),'attendance':round(sum(s['attendance'] for s in ss)/n,1),'high_risk':sum(s['risk']=='High' for s in ss),'medium_risk':sum(s['risk']=='Medium' for s in ss),'low_risk':sum(s['risk']=='Low' for s in ss),'placement_rate':round(100*sum(s['placement']>=70 for s in ss)/n,1),'avg_score':round(sum(s['score'] for s in ss)/n,1),'departments':list(depts.values()),'segments':segment(ss)}
def segment(ss):
 groups={'High academics · low placement':[],'Low attendance · good marks':[],'Academic support needed':[],'Placement preparation needed':[],'On track':[]}
 for s in ss:
  if s['cgpa']>=8 and s['placement']<55:k='High academics · low placement'
  elif s['attendance']<70 and s['marks']>=60:k='Low attendance · good marks'
  elif s['academic_risk']=='High' or s['backlogs']>=2:k='Academic support needed'
  elif s['placement']<55:k='Placement preparation needed'
  elif s['risk']=='Low':k='On track'
  else:continue
  groups[k].append({'sid':s['sid'],'name':s['name']})
 return [{'name':k,'count':len(v),'students':v} for k,v in groups.items()]
@app.get('/api/analytics/segments')
def segments(u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):return segment([student_json(s) for s in db.query(Student).all()])
@app.post('/api/marks')
def add_mark(data:dict,u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 s=db.query(Student).filter_by(sid=data.get('sid')).first();scorev=float(data.get('score',-1));maximum=float(data.get('maximum',100))
 if not s or maximum<=0 or not 0<=scorev<=maximum:raise HTTPException(400,'Check student ID and mark range.')
 db.add(Mark(sid=s.sid,subject=data.get('subject','General'),assessment=data.get('assessment','Internal'),score=scorev,maximum=maximum));s.marks=round((s.marks+scorev/maximum*100)/2,1);db.commit();audit(db,u['login'],'mark_saved',s.sid);return {'message':'Marks saved. Student score and risk refreshed.','student':student_json(s)}
@app.get('/api/marks')
def get_marks(sid:str='',u=Depends(userdep),db:Session=Depends(getdb)):
 if u['role']=='student':sid=u['login']
 q=db.query(Mark)
 if sid:q=q.filter_by(sid=sid)
 return [{'id':m.id,'sid':m.sid,'subject':m.subject,'assessment':m.assessment,'score':m.score,'maximum':m.maximum,'created':m.created.isoformat()} for m in q.order_by(Mark.created.desc()).limit(200).all()]
@app.post('/api/attendance')
def add_att(data:dict,u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 sid=data.get('sid');s=db.query(Student).filter_by(sid=sid).first();status=data.get('status')
 if not s or status not in ('present','absent','excused'):raise HTTPException(400,'Invalid student or attendance status.')
 subject=data.get('subject','General');day=data.get('day',datetime.now().date().isoformat());a=db.query(Attendance).filter_by(sid=sid,subject=subject,day=day).first()
 if a:a.status=status
 else:db.add(Attendance(sid=sid,subject=subject,day=day,status=status))
 rows=db.query(Attendance).filter_by(sid=sid).all()
 if rows:s.attendance=round(100*sum(x.status=='present' for x in rows)/len(rows),1)
 db.commit();audit(db,u['login'],'attendance_saved',sid);return {'message':'Attendance saved.','student':student_json(s)}
@app.get('/api/attendance')
def get_att(sid:str='',u=Depends(userdep),db:Session=Depends(getdb)):
 if u['role']=='student':sid=u['login']
 q=db.query(Attendance)
 if sid:q=q.filter_by(sid=sid)
 return [{'id':a.id,'sid':a.sid,'subject':a.subject,'day':a.day,'status':a.status} for a in q.order_by(Attendance.created.desc()).limit(200).all()]
@app.get('/api/messages')
def messages(u=Depends(userdep),db:Session=Depends(getdb)):
 q=db.query(Message)
 if u['role']=='student':q=q.filter_by(sid=u['login'])
 return [{'id':m.id,'sid':m.sid,'sender':m.sender,'subject':m.subject,'body':m.body,'kind':m.kind,'reply':m.reply,'created':m.created.isoformat()} for m in q.order_by(Message.created.desc()).all()]
@app.post('/api/messages')
def send_message(data:dict,u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 sid=data.get('sid')
 if not db.query(Student).filter_by(sid=sid).first():raise HTTPException(404,'Student not found.')
 m=Message(sid=sid,sender=u['login'],subject=data.get('subject','Message'),body=data.get('body',''),kind=data.get('kind','message'));db.add(m);db.commit();audit(db,u['login'],'message_sent',sid);return {'message':'Sent to student inbox.'}
@app.post('/api/messages/{mid}/reply')
def reply(mid:int,data:dict,u=Depends(userdep),db:Session=Depends(getdb)):
 m=db.query(Message).filter_by(id=mid).first()
 if not m:raise HTTPException(404,'Message not found.')
 if u['role']=='student' and m.sid!=u['login']:raise HTTPException(403,'Not your message.')
 m.reply=data.get('reply','');db.commit();return {'message':'Reply saved.'}
@app.get('/api/interventions')
def get_interventions(u=Depends(userdep),db:Session=Depends(getdb)):
 q=db.query(Intervention)
 if u['role']=='student':q=q.filter_by(sid=u['login'])
 return [{'id':i.id,'sid':i.sid,'title':i.title,'action':i.action,'due':i.due,'status':i.status,'remarks':i.remarks} for i in q.order_by(Intervention.created.desc()).all()]
@app.post('/api/interventions')
def add_intervention(data:dict,u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 if not db.query(Student).filter_by(sid=data.get('sid')).first():raise HTTPException(404,'Student not found.')
 i=Intervention(sid=data['sid'],title=data.get('title','Support plan'),action=data.get('action',''),due=data.get('due',''));db.add(i);db.commit();return {'message':'Intervention created.'}
@app.patch('/api/interventions/{iid}')
def patch_intervention(iid:int,data:dict,u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 i=db.query(Intervention).filter_by(id=iid).first()
 if not i:raise HTTPException(404,'Not found.')
 if data.get('status') not in ('pending','in progress','completed','cancelled'):raise HTTPException(400,'Invalid status.')
 i.status=data['status'];i.remarks=data.get('remarks','');db.commit();return {'message':'Updated.'}
@app.post('/api/resources')
async def upload_resource(title:str=Form(...),subject:str=Form('General'),file:UploadFile=File(...),u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 ext=Path(file.filename or '').suffix.lower()
 if ext not in ('.pdf','.txt','.docx','.pptx','.png','.jpg','.jpeg'):raise HTTPException(400,'Unsupported file type.')
 content=await file.read()
 if len(content)>10*1024*1024:raise HTTPException(413,'Maximum file size is 10MB.')
 stored=secrets.token_hex(16)+ext;(UPLOADS/stored).write_bytes(content);db.add(Resource(title=title,subject=subject,filename=Path(file.filename).name,stored=stored,uploader=u['login']));db.commit();return {'message':'Uploaded.'}
@app.get('/api/resources')
def resources(u=Depends(userdep),db:Session=Depends(getdb)):return [{'id':r.id,'title':r.title,'subject':r.subject,'filename':r.filename,'uploader':r.uploader} for r in db.query(Resource).order_by(Resource.created.desc()).all()]
@app.get('/api/resources/{rid}/download')
def download(rid:int,u=Depends(userdep),db:Session=Depends(getdb)):
 r=db.query(Resource).filter_by(id=rid).first()
 if not r or not (UPLOADS/r.stored).exists():raise HTTPException(404,'Resource not found.')
 return FileResponse(UPLOADS/r.stored,filename=r.filename)
@app.post('/api/feedback')
def feedback(data:dict,u=Depends(allow('student')),db:Session=Depends(getdb)):
 db.add(Feedback(sid=u['login'],faculty=data.get('faculty',''),body=data.get('body','')));db.commit();return {'message':'Feedback submitted privately.'}
@app.get('/api/admin/feedback')
def admin_feedback(u=Depends(allow('admin')),db:Session=Depends(getdb)):return [{'sid':f.sid,'faculty':f.faculty,'body':f.body,'created':f.created.isoformat()} for f in db.query(Feedback).order_by(Feedback.created.desc()).all()]
@app.post('/api/import/students')
async def import_students(file:UploadFile=File(...),u=Depends(allow('admin')),db:Session=Depends(getdb)):
 raw=await file.read();name=(file.filename or '').lower()
 try:
  if name.endswith('.csv'):rows=list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))))
  elif name.endswith('.xlsx'):
   from openpyxl import load_workbook
   vals=list(load_workbook(io.BytesIO(raw),read_only=True,data_only=True).active.values);rows=[dict(zip(vals[0],r)) for r in vals[1:]] if vals else []
  else:raise HTTPException(400,'Upload CSV or XLSX.')
 except HTTPException:raise
 except Exception as e:raise HTTPException(400,f'Unable to read file: {e}')
 created=0;errors=[]
 for ix,row in enumerate(rows,2):
  try:
   sid=str(row.get('sid') or row.get('student_id') or row.get('Student ID') or '').strip()
   if not sid:raise ValueError('student_id is required')
   s=db.query(Student).filter_by(sid=sid).first()
   if not s:
    s=Student(sid=sid,name=str(row.get('name') or row.get('Name') or sid));db.add(s);created+=1
    if not db.query(User).filter_by(login=sid).first():db.add(User(login=sid,password=hashpw('ChangeMe123!'),role='student'))
   for k in ('name','department','year','section','cgpa','attendance','marks','backlogs','lms','engagement','skills','placement','assignments','email','phone'):
    v=row.get(k) if row.get(k) not in (None,'') else row.get(k.title())
    if v not in (None,''):setattr(s,k,int(float(v)) if k in ('year','backlogs') else float(v) if k in ('cgpa','attendance','marks','lms','engagement','skills','placement','assignments') else str(v))
  except Exception as e:errors.append({'row':ix,'error':str(e)})
 db.commit();audit(db,u['login'],'student_import',f'created={created}; errors={len(errors)}');return {'created':created,'errors':errors,'rows':len(rows),'temporary_password':'ChangeMe123!'}
@app.get('/api/reports/students.csv')
def report(u=Depends(allow('faculty','admin')),db:Session=Depends(getdb)):
 out=io.StringIO();w=csv.writer(out);w.writerow(['student_id','name','department','year','cgpa','attendance','internal_marks','backlogs','success_score','risk','placement_readiness'])
 for s in db.query(Student).all():d=student_json(s);w.writerow([s.sid,s.name,s.department,s.year,s.cgpa,s.attendance,s.marks,s.backlogs,d['score'],d['risk'],s.placement])
 return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=unisphere-report.csv'})
@app.get('/api/admin/audit')
def logs(u=Depends(allow('admin')),db:Session=Depends(getdb)):return [{'actor':x.actor,'action':x.action,'detail':x.detail,'created':x.created.isoformat()} for x in db.query(Audit).order_by(Audit.created.desc()).limit(200).all()]
@app.post('/api/auth/forgot-password')
def forgot(data:dict):return {'message':'Password recovery requires an SMS provider. Configure one before deployment; this endpoint intentionally does not reveal OTPs.'}
@app.get('/api/admin/settings')
def settings(u=Depends(allow('admin'))):return {'weights':{'academic':30,'attendance':20,'lms':15,'engagement':10,'skills':10,'placement':15},'risk_thresholds':{'high':50,'medium':70},'note':'Baseline formula is documented in README.'}
FRONT=ROOT/'frontend';app.mount('/',StaticFiles(directory=FRONT,html=True),name='frontend')
