import express from 'express';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import { Server } from 'socket.io';

const dir = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.CORS_ORIGIN || '*'} });
app.use(helmet({contentSecurityPolicy:false}));
app.use(cors());
app.use(express.json({limit:'1mb'}));
app.use(express.static(path.join(dir,'public')));
const secret = process.env.JWT_SECRET;
if (!secret) { console.error('JWT_SECRET is required'); process.exit(1); }
const pool = mysql.createPool({
 host:process.env.MYSQLHOST || process.env.MYSQL_HOST,
 port:Number(process.env.MYSQLPORT || process.env.MYSQL_PORT || 3306),
 user:process.env.MYSQLUSER || process.env.MYSQL_USER,
 password:process.env.MYSQLPASSWORD || process.env.MYSQL_PASSWORD,
 database:process.env.MYSQLDATABASE || process.env.MYSQL_DATABASE,
 waitForConnections:true, connectionLimit:10, queueLimit:0
});
await pool.query(`CREATE TABLE IF NOT EXISTS users (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(64) NOT NULL UNIQUE,
 password_hash VARCHAR(255) NOT NULL,
 display_name VARCHAR(100) NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS messages (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 sender_id BIGINT UNSIGNED NOT NULL,
 recipient_id BIGINT UNSIGNED NOT NULL,
 body TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 INDEX ix_sender_recipient (sender_id,recipient_id,id),
 INDEX ix_recipient_sender (recipient_id,sender_id,id),
 CONSTRAINT fk_sender FOREIGN KEY(sender_id) REFERENCES users(id),
 CONSTRAINT fk_recipient FOREIGN KEY(recipient_id) REFERENCES users(id)
)`);
const auth=(req,res,next)=>{try{req.user=jwt.verify((req.headers.authorization||'').replace(/^Bearer\\s+/i,''),secret);next()}catch{res.status(401).json({error:'Vui lòng đăng nhập lại.'})}};
const publicUser=u=>({id:Number(u.id),username:u.username,displayName:u.display_name});
app.get('/api/health',async(_req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,database:'mysql'})}catch{res.status(503).json({ok:false,error:'database_unavailable'})}});
app.post('/api/register',async(req,res)=>{
 const username=String(req.body.username||'').trim().toLowerCase(), password=String(req.body.password||''), displayName=String(req.body.displayName||req.body.username||'').trim().slice(0,100);
 if(!/^[a-z0-9_.-]{3,64}$/.test(username)||password.length<8)return res.status(400).json({error:'Tên đăng nhập 3–64 ký tự (a-z, 0-9, . _ -); mật khẩu tối thiểu 8 ký tự.'});
 try{const hash=await bcrypt.hash(password,12);const [r]=await pool.execute('INSERT INTO users(username,password_hash,display_name) VALUES(?,?,?)',[username,hash,displayName||username]);const user={id:r.insertId,username,display_name:displayName||username};res.status(201).json({user:publicUser(user),token:jwt.sign({id:user.id,username},secret,{expiresIn:'30d'})})}catch(e){res.status(e.code==='ER_DUP_ENTRY'?409:500).json({error:e.code==='ER_DUP_ENTRY'?'Tên đăng nhập đã tồn tại.':'Không thể tạo tài khoản.'})}
});
app.post('/api/login',async(req,res)=>{const username=String(req.body.username||'').trim().toLowerCase();const [rows]=await pool.execute('SELECT * FROM users WHERE username=? LIMIT 1',[username]);if(!rows.length||!(await bcrypt.compare(String(req.body.password||''),rows[0].password_hash)))return res.status(401).json({error:'Sai tên đăng nhập hoặc mật khẩu.'});const u=rows[0];res.json({user:publicUser(u),token:jwt.sign({id:u.id,username:u.username},secret,{expiresIn:'30d'})})});
app.get('/api/users',auth,async(req,res)=>{const [rows]=await pool.execute('SELECT id,username,display_name FROM users WHERE id<>? ORDER BY username LIMIT 200',[req.user.id]);res.json(rows.map(publicUser))});
app.get('/api/messages/:userId',auth,async(req,res)=>{const other=Number(req.params.userId);const [rows]=await pool.execute(`SELECT id,sender_id,recipient_id,body,created_at FROM messages WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) ORDER BY id DESC LIMIT 200`,[req.user.id,other,other,req.user.id]);res.json(rows.reverse())});
app.post('/api/messages/:userId',auth,async(req,res)=>{const recipient=Number(req.params.userId),body=String(req.body.body||'').trim();if(!Number.isSafeInteger(recipient)||recipient<1||!body||body.length>5000)return res.status(400).json({error:'Tin nhắn không hợp lệ.'});if(recipient===Number(req.user.id))return res.status(400).json({error:'Không thể nhắn cho chính mình.'});const [users]=await pool.execute('SELECT id FROM users WHERE id=?',[recipient]);if(!users.length)return res.status(404).json({error:'Không tìm thấy người dùng.'});const [r]=await pool.execute('INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)',[req.user.id,recipient,body]);const [rows]=await pool.execute('SELECT id,sender_id,recipient_id,body,created_at FROM messages WHERE id=?',[r.insertId]);const m=rows[0];io.to('user:'+recipient).emit('message',m);io.to('user:'+req.user.id).emit('message',m);res.status(201).json(m)});
io.use((s,next)=>{try{s.user=jwt.verify(s.handshake.auth?.token||'',secret);next()}catch{next(new Error('Unauthorized'))}});
io.on('connection',s=>s.join('user:'+s.user.id));
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Lỗi máy chủ.'})});
server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('XiaoFan listening'));
