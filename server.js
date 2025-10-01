// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  pingTimeout: 60000,
  pingInterval: 25000,
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// 🔒 إعدادات الأمان الأساسية
app.use((req, res, next) => {
  // الحماية من XSS
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // منع MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // منع clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// 🔄 Rate Limiting يدوي
const requestCounts = new Map();
setInterval(() => {
  requestCounts.clear();
}, 60000); // مسح العد كل دقيقة

function checkRateLimit(ip) {
  const now = Date.now();
  const windowStart = now - 60000; // نافذة 1 دقيقة
  
  let requests = requestCounts.get(ip) || [];
  requests = requests.filter(time => time > windowStart);
  
  if (requests.length >= 100) { // 100 طلب في الدقيقة
    return false;
  }
  
  requests.push(now);
  requestCounts.set(ip, requests);
  return true;
}

// تطبيق Rate Limiting
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkRateLimit(ip)) {
    return res.status(429).send('تم تجاوز الحد المسموح من الطلبات');
  }
  next();
});

// خدمة الملفات الثابتة
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  etag: false
}));

// 🔐 توليد مفتاح جلسة آمن
function generateSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

// 🔄 تخزين البيانات مع استمرارية
let onlineUsers = [];
let messages = [];
const userSessions = new Map();
const messageLimits = new Map();

// 🕒 تنظيف البيانات القديمة تلقائياً
setInterval(() => {
  const now = Date.now();
  // مسح حدود الرسائل القديمة
  for (const [userId, timestamps] of messageLimits.entries()) {
    const recent = timestamps.filter(time => now - time < 60000);
    if (recent.length === 0) {
      messageLimits.delete(userId);
    } else {
      messageLimits.set(userId, recent);
    }
  }
}, 30000); // كل 30 ثانية

// 🔍 تحقق من الصلاحيات
function hasPermission(user, action) {
  if (!user) return false;
  
  const permissions = {
    'kick-user': ['admin', 'moderator'],
    'delete-message': ['admin', 'moderator'],
    'clear-chat': ['admin']
  };
  return permissions[action]?.includes(user.role);
}

// ✉️ تحقق من الرسالة
function validateMessage(message) {
  if (!message || typeof message !== 'string') return false;
  
  const trimmed = message.trim();
  if (trimmed.length === 0) return false;
  if (trimmed.length > 1000) return false;
  
  // منع محتوى ضار
  const harmfulPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe/gi,
    /<object/gi,
    /<embed/gi
  ];
  
  return !harmfulPatterns.some(pattern => pattern.test(trimmed));
}

// 👤 تحقق من اسم المستخدم
function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;
  
  const trimmed = username.trim();
  if (trimmed.length < 2 || trimmed.length > 20) return false;
  
  // منع أحرف خاصة خطيرة
  const dangerousChars = /[<>{}[\]\\]/;
  if (dangerousChars.test(trimmed)) return false;
  
  // أحرف مسموحة: عربية، إنجليزية، أرقام، مسافات، _
  const validPattern = /^[a-zA-Z0-9\u0600-\u06FF\s_-]+$/;
  return validPattern.test(trimmed);
}

// 🔄 توليد لون عشوائي للصورة الرمزية
function generateRandomColor() {
  const colors = ['#2F5C73', '#28a745', '#dc3545', '#ffc107', '#6f42c1', '#e83e8c', '#fd7e14'];
  return colors[Math.floor(Math.random() * colors.length)];
}

io.on('connection', (socket) => {
  console.log('مستخدم جديد متصل:', socket.id);
  
  // 🔄 إضافة IP المستخدم للأمان
  const clientIp = socket.handshake.address;
  console.log(`IP المستخدم: ${clientIp}`);
  
  // 🔄 إعداد إعادة الاتصال
  socket.conn.on('heartbeat', () => {
    socket.emit('heartbeat', { timestamp: Date.now() });
  });

  // 📨 إرسال البيانات الحالية للمستخدم الجديد
  socket.emit('current-data', {
    users: onlineUsers,
    messages: messages.slice(-50),
    messageCount: messages.length,
    sessionId: generateSessionId()
  });

  // 🔐 انضمام مستخدم جديد
  socket.on('user-joined', (userData) => {
    try {
      // تحقق من البيانات
      if (!userData.username || typeof userData.username !== 'string') {
        socket.emit('error', 'بيانات المستخدم غير صالحة');
        return;
      }

      // تحقق من صحة اسم المستخدم
      if (!validateUsername(userData.username)) {
        socket.emit('error', 'اسم المستخدم يجب أن يكون بين 2 و 20 حرفاً ويحتوي على أحرف مسموحة فقط');
        return;
      }

      const username = userData.username.trim();
      
      // تجنب تكرار الأسماء (حساس لحالة الأحرف)
      const existingUser = onlineUsers.find(u => u.username.toLowerCase() === username.toLowerCase());
      if (existingUser) {
        socket.emit('username-taken', 'اسم المستخدم مستخدم بالفعل');
        return;
      }

      // تحديد دور المستخدم
      let userRole = 'user';
      const adminUsers = ['admin', 'administrator', 'مشرف', 'ادمن', 'مدير'];
      const moderatorUsers = ['moderator', 'مشرف', 'مراقب', 'mod'];
      
      const lowerUsername = username.toLowerCase();
      if (adminUsers.some(admin => lowerUsername.includes(admin.toLowerCase()))) {
        userRole = 'admin';
      } else if (moderatorUsers.some(mod => lowerUsername.includes(mod.toLowerCase()))) {
        userRole = 'moderator';
      }

      const user = {
        id: socket.id,
        username: username,
        role: userRole,
        avatar: generateRandomColor(),
        joinedAt: new Date().toISOString(),
        sessionId: generateSessionId(),
        ip: clientIp
      };
      
      onlineUsers.push(user);
      userSessions.set(socket.id, user.sessionId);
      
      // إرسال تحديث للجميع
      io.emit('update-users', onlineUsers);
      io.emit('user-count', onlineUsers.length);
      
      // إرسال رسالة ترحيب
      const welcomeMessage = {
        id: Date.now() + Math.random(),
        username: 'النظام',
        message: `مرحباً ${username}! انضم إلى الدردشة.`,
        time: new Date().toLocaleTimeString('ar-EG'),
        type: 'system',
        timestamp: Date.now()
      };
      
      messages.push(welcomeMessage);
      io.emit('new-message', welcomeMessage);
      
      console.log(`المستخدم ${username} انضم إلى الدردشة (دور: ${userRole})`);
      
    } catch (error) {
      console.error('خطأ في انضمام المستخدم:', error);
      socket.emit('error', 'حدث خطأ في الانضمام');
    }
  });

  // ✉️ استقبال رسالة جديدة
  socket.on('new-message', (messageData) => {
    try {
      const user = onlineUsers.find(u => u.id === socket.id);
      if (!user) {
        socket.emit('error', 'يجب الانضمام أولاً');
        return;
      }

      // 🔄 Rate Limiting للرسائل
      const now = Date.now();
      const userMessages = messageLimits.get(socket.id) || [];
      const recentMessages = userMessages.filter(time => now - time < 60000);
      
      if (recentMessages.length >= 15) {
        socket.emit('error', 'تم تجاوز الحد المسموح (15 رسالة في الدقيقة)');
        return;
      }

      // تحقق من صحة الرسالة
      if (!validateMessage(messageData.message)) {
        socket.emit('error', 'الرسالة غير صالحة');
        return;
      }

      const message = {
        id: Date.now() + Math.random(),
        username: user.username,
        userId: socket.id,
        message: messageData.message.trim(),
        role: user.role,
        time: new Date().toLocaleTimeString('ar-EG'),
        type: 'user',
        timestamp: Date.now()
      };
      
      messages.push(message);
      recentMessages.push(now);
      messageLimits.set(socket.id, recentMessages);
      
      // حفظ فقط آخر 200 رسالة
      if (messages.length > 200) {
        messages = messages.slice(-200);
      }
      
      io.emit('new-message', message);
      
    } catch (error) {
      console.error('خطأ في إرسال الرسالة:', error);
      socket.emit('error', 'حدث خطأ في إرسال الرسالة');
    }
  });

  // 🚫 طرد مستخدم
  socket.on('kick-user', (data) => {
    try {
      const adminUser = onlineUsers.find(u => u.id === socket.id);
      if (!adminUser || !hasPermission(adminUser, 'kick-user')) {
        socket.emit('error', 'ليس لديك صلاحية');
        return;
      }

      // تحقق من البيانات
      if (!data.username || typeof data.username !== 'string') {
        socket.emit('error', 'بيانات غير صالحة');
        return;
      }

      const user = onlineUsers.find(u => u.username === data.username);
      if (user) {
        // إرسال إشعار الطرد للمستخدم
        io.to(user.id).emit('kicked', data.reason || 'تم طردك من الدردشة');
        
        // فصل المستخدم بعد ثانية
        setTimeout(() => {
          const userSocket = io.sockets.sockets.get(user.id);
          if (userSocket) {
            userSocket.disconnect(true);
          }
        }, 1000);
        
        // إرسال إشعار للجميع
        socket.broadcast.emit('user-kicked', {
          username: data.username,
          by: adminUser.username,
          reason: data.reason || 'بدون سبب'
        });
        
        console.log(`تم طرد ${data.username} بواسطة ${adminUser.username}`);
      }
    } catch (error) {
      console.error('خطأ في طرد المستخدم:', error);
      socket.emit('error', 'حدث خطأ في طرد المستخدم');
    }
  });

  // 🗑️ حذف رسالة
  socket.on('delete-message', (messageId) => {
    try {
      const user = onlineUsers.find(u => u.id === socket.id);
      if (!user || !hasPermission(user, 'delete-message')) {
        socket.emit('error', 'ليس لديك صلاحية');
        return;
      }

      const messageIndex = messages.findIndex(msg => msg.id === messageId);
      if (messageIndex !== -1) {
        messages.splice(messageIndex, 1);
        io.emit('message-deleted', messageId);
        console.log(`تم حذف رسالة بواسطة ${user.username}`);
      }
    } catch (error) {
      console.error('خطأ في حذف الرسالة:', error);
      socket.emit('error', 'حدث خطأ في حذف الرسالة');
    }
  });

  // 🧹 مسح جميع الرسائل
  socket.on('clear-chat', (data) => {
    try {
      const user = onlineUsers.find(u => u.id === socket.id);
      if (!user || !hasPermission(user, 'clear-chat')) {
        socket.emit('error', 'ليس لديك صلاحية');
        return;
      }

      messages = [];
      io.emit('chat-cleared', { 
        by: user.username,
        timestamp: new Date().toLocaleTimeString('ar-EG')
      });
      
      console.log(`تم مسح الدردشة بواسطة ${user.username}`);
    } catch (error) {
      console.error('خطأ في مسح الدردشة:', error);
      socket.emit('error', 'حدث خطأ في مسح الدردشة');
    }
  });

  // 🔄 استعادة الاتصال
  socket.on('restore-session', (sessionData) => {
    try {
      const user = onlineUsers.find(u => u.sessionId === sessionData.sessionId);
      if (user) {
        // تحديث معرف الاتصال
        user.id = socket.id;
        userSessions.set(socket.id, user.sessionId);
        
        socket.emit('session-restored', {
          user: user,
          messages: messages.slice(-50),
          users: onlineUsers
        });
        
        console.log(`تم استعادة جلسة المستخدم: ${user.username}`);
      } else {
        socket.emit('error', 'لم يتم العثور على الجلسة');
      }
    } catch (error) {
      console.error('خطأ في استعادة الجلسة:', error);
      socket.emit('error', 'فشل في استعادة الجلسة');
    }
  });

  // أحداث المايكروفونات
  socket.on('mic-joined', (data) => {
    const user = onlineUsers.find(u => u.id === socket.id);
    if (user) {
      console.log(`المستخدم ${user.username} انضم إلى المايكروفون ${data.micId}`);
    }
  });

  socket.on('mic-left', (data) => {
    const user = onlineUsers.find(u => u.id === socket.id);
    if (user) {
      console.log(`المستخدم ${user.username} ترك المايكروفون بعد ${data.timeSpent} دقيقة`);
    }
  });

  socket.on('mic-kicked', (data) => {
    const adminUser = onlineUsers.find(u => u.id === socket.id);
    if (adminUser && hasPermission(adminUser, 'kick-user')) {
      console.log(`تم طرد ${data.username} من المايكروفون بواسطة ${adminUser.username}`);
    }
  });

  // 📞 فصل مستخدم
  socket.on('disconnect', (reason) => {
    const user = onlineUsers.find(u => u.id === socket.id);
    if (user) {
      // تأخير إزالة المستخدم للسماح بإعادة الاتصال
      setTimeout(() => {
        const userStillConnected = onlineUsers.find(u => u.username === user.username && u.id !== socket.id);
        
        if (!userStillConnected) {
          onlineUsers = onlineUsers.filter(u => u.id !== socket.id);
          userSessions.delete(socket.id);
          messageLimits.delete(socket.id);
          
          io.emit('update-users', onlineUsers);
          io.emit('user-count', onlineUsers.length);
          
          const leaveMessage = {
            id: Date.now() + Math.random(),
            username: 'النظام',
            message: `${user.username} غادر الدردشة.`,
            time: new Date().toLocaleTimeString('ar-EG'),
            type: 'system',
            timestamp: Date.now()
          };
          
          messages.push(leaveMessage);
          io.emit('new-message', leaveMessage);
          
          console.log(`المستخدم ${user.username} غادر الدردشة (سبب: ${reason})`);
        }
      }, 5000); // انتظار 5 ثوانٍ قبل إزالة المستخدم
    }
  });

  // ❤️ التحقق من الاتصال
  socket.on('ping', (data) => {
    socket.emit('pong', { ...data, serverTime: Date.now() });
  });
});

// 🛡️ معالجة الأخطاء غير المتوقعة
process.on('uncaughtException', (error) => {
  console.error('خطأ غير متوقع:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('رفض غير معالج:', reason);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🛡️ الخادم يعمل على المنفذ ${PORT}`);
  console.log(`🌐 افتح http://localhost:${PORT} في المتصفح`);
  console.log(`🔒 وضع الأمان: نشط`);
  console.log(`📊 الميزات:`);
  console.log(`   - تحقق من صحة البيانات`);
  console.log(`   - Rate Limiting`);
  console.log(`   - منع XSS`);
  console.log(`   - إعادة اتصال تلقائي`);
  console.log(`   - إدارة الصلاحيات`);
});