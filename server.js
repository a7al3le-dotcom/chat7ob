// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// خدمة الملفات الثابتة
app.use(express.static(path.join(__dirname, 'public')));

let onlineUsers = [];
let messages = [];

io.on('connection', (socket) => {
  console.log('مستخدم جديد متصل:', socket.id);

  // إرسال البيانات الحالية للمستخدم الجديد
  socket.emit('current-data', {
    users: onlineUsers,
    messages: messages.slice(-50), // آخر 50 رسالة
    messageCount: messages.length
  });

  // انضمام مستخدم جديد
  socket.on('user-joined', (userData) => {
    const user = {
      id: socket.id,
      username: userData.username,
      role: userData.role,
      avatar: userData.avatar || `#${Math.floor(Math.random()*16777215).toString(16)}`
    };
    
    // تجنب تكرار الأسماء
    const existingUser = onlineUsers.find(u => u.username === userData.username);
    if (existingUser) {
      socket.emit('username-taken', 'اسم المستخدم مستخدم بالفعل');
      return;
    }
    
    onlineUsers.push(user);
    
    // إرسال تحديث للجميع
    io.emit('update-users', onlineUsers);
    io.emit('user-count', onlineUsers.length);
    
    // إرسال رسالة ترحيب
    const welcomeMessage = {
      id: Date.now(),
      username: 'النظام',
      message: `مرحباً ${userData.username}! انضم إلى الدردشة.`,
      time: new Date().toLocaleTimeString('ar-EG'),
      type: 'system'
    };
    
    messages.push(welcomeMessage);
    io.emit('new-message', welcomeMessage);
    
    console.log(`المستخدم ${userData.username} انضم إلى الدردشة`);
  });

  // استقبال رسالة جديدة
  socket.on('new-message', (messageData) => {
    const message = {
      id: Date.now(),
      username: messageData.username,
      message: messageData.message,
      role: messageData.role,
      time: new Date().toLocaleTimeString('ar-EG'),
      type: 'user'
    };
    
    messages.push(message);
    
    // حفظ فقط آخر 100 رسالة
    if (messages.length > 100) {
      messages = messages.slice(-100);
    }
    
    io.emit('new-message', message);
  });

  // طرد مستخدم
  socket.on('kick-user', (data) => {
    const user = onlineUsers.find(u => u.username === data.username);
    if (user) {
      io.to(user.id).emit('kicked', data.reason);
      socket.broadcast.emit('user-kicked', {
        username: data.username,
        by: data.by,
        reason: data.reason
      });
    }
  });

  // حذف رسالة
  socket.on('delete-message', (messageId) => {
    messages = messages.filter(msg => msg.id !== messageId);
    io.emit('message-deleted', messageId);
  });

  // مسح جميع الرسائل
  socket.on('clear-chat', (data) => {
    messages = [];
    io.emit('chat-cleared', { by: data.by });
  });

  // فصل مستخدم
  socket.on('disconnect', () => {
    const user = onlineUsers.find(u => u.id === socket.id);
    if (user) {
      onlineUsers = onlineUsers.filter(u => u.id !== socket.id);
      
      io.emit('update-users', onlineUsers);
      io.emit('user-count', onlineUsers.length);
      
      const leaveMessage = {
        id: Date.now(),
        username: 'النظام',
        message: `${user.username} غادر الدردشة.`,
        time: new Date().toLocaleTimeString('ar-EG'),
        type: 'system'
      };
      
      messages.push(leaveMessage);
      io.emit('new-message', leaveMessage);
      
      console.log(`المستخدم ${user.username} غادر الدردشة`);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`الخادم يعمل على المنفذ ${PORT}`);
  console.log(`افتح http://localhost:${PORT} في المتصفح`);
});