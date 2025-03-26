// HTML 模板
const TEMPLATES = {
  // 管理后台登录页
  login: (siteKey, error = '', csrfToken = '') => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理登录</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
    .form-group { margin-bottom: 15px; }
    label { display: block; margin-bottom: 5px; }
    input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
    button { background: #4285f4; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
    .error { color: #d93025; margin-bottom: 15px; }
  </style>
</head>
<body>
  <h2>管理后台登录</h2>
  ${error ? `<div class="error" role="alert">${escapeHTML(error)}</div>` : ''}
  <form method="POST">
    <input type="hidden" name="csrf_token" value="${csrfToken}">
    <div class="form-group">
      <label for="password">管理密码</label>
      <input type="password" id="password" name="password" required autocomplete="off">
    </div>
    <div class="form-group">
      <div class="cf-turnstile" data-sitekey="${escapeHTML(siteKey)}"></div>
    </div>
    <button type="submit">登录</button>
  </form>
</body>
</html>
  `,

  // 管理后台主页
  admin: (routes, csrfToken = '') => {
    const routeRows = routes.map((route, index) => `
      <tr id="route-row-${index}">
        <td>${escapeHTML(route.path)}</td>
        <td>${route.type === 'redirect' ? '重定向' : '自定义内容'}</td>
        <td>${route.type === 'redirect' ? escapeHTML(route.target) : '已存储内容'}</td>
        <td>${escapeHTML(route.remark || '-')}</td>
        <td id="route-status-${index}">${route.enabled ? '启用' : '禁用'}</td>
        <td>
          <button class="edit-btn" data-index="${index}">编辑</button>
          <button class="delete-btn" data-index="${index}">删除</button>
          <button class="toggle-btn" data-index="${index}" data-enabled="${route.enabled}">${route.enabled ? '禁用' : '启用'}</button>
        </td>
      </tr>
    `).join('');

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>网关管理后台</title>
  <link rel="stylesheet" href="/admin/styles.css">
</head>
<body>
  <div class="header">
    <h2>网关规则管理</h2>
    <button class="logout" id="logout-btn">退出登录</button>
  </div>

  <button id="add-rule-btn">添加新规则</button>
  
  <h3>规则列表</h3>
  <div id="notification-area"></div>
  <table>
    <thead>
      <tr>
        <th>路径</th>
        <th>类型</th>
        <th>目标</th>
        <th>备注</th>
        <th>状态</th>
        <th>操作</th>
      </tr>
    </thead>
    <tbody id="routes-table">
      ${routeRows}
    </tbody>
  </table>

  <div id="overlay"></div>
  <div id="form-container">
    <h3 id="form-title">添加规则</h3>
    <form id="route-form">
      <input type="hidden" name="csrf_token" value="${csrfToken}">
      <input type="hidden" id="route-index" value="">
      <div class="form-group">
        <label for="path">路径 (必须以 / 开头)</label>
        <input type="text" id="path" required pattern="^\/.*">
      </div>
      <div class="form-group">
        <label for="type">类型</label>
        <select id="type">
          <option value="redirect">重定向</option>
          <option value="content">自定义内容</option>
        </select>
      </div>
      <div class="form-group" id="target-group">
        <label for="target">重定向目标网址</label>
        <input type="url" id="target">
      </div>
      <div class="form-group" id="content-group" style="display:none;">
        <label for="content">自定义内容 (HTML/纯文本)</label>
        <textarea id="content" rows="10"></textarea>
      </div>
      <div class="form-group">
        <label for="remark">备注</label>
        <input type="text" id="remark">
      </div>
      <div class="form-group checkbox-group">
        <label for="enabled" class="checkbox-label">
          <input type="checkbox" id="enabled" checked>
          <span class="checkbox-text">启用此规则</span>
        </label>
      </div>
      <button type="submit" id="submit-btn">保存</button>
      <button type="button" id="cancel-btn">取消</button>
    </form>
  </div>

  <!-- 确认对话框 -->
  <div id="confirm-dialog">
    <div class="dialog-content">
      <h3 id="confirm-title">确认操作</h3>
      <p id="confirm-message">确定要执行此操作吗？</p>
      <div class="dialog-buttons">
        <button id="confirm-yes">确定</button>
        <button id="confirm-no">取消</button>
      </div>
    </div>
  </div>

  <!-- 分离的JavaScript -->
  <script src="/admin/scripts.js"></script>
  <script>
    // 初始化应用
    const app = new AdminApp({
      routes: ${JSON.stringify(routes)},
      csrfToken: "${csrfToken}"
    });
    app.init();
  </script>
</body>
</html>
    `;
  },

  // 管理后台CSS样式
  adminStyles: `
body { font-family: system-ui, -apple-system, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
button { background: #4285f4; color: white; border: none; padding: 5px 10px; margin-right: 5px; border-radius: 4px; cursor: pointer; }
.form-group { margin-bottom: 15px; }
label { display: block; margin-bottom: 5px; }
input, textarea, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
#overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 100;}
#form-container { display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 20px; border-radius: 8px; width: 80%; max-width: 500px; z-index: 101;}
.header { display: flex; justify-content: space-between; align-items: center; }
.logout { background: #f44336; }
.checkbox-group { margin-bottom: 15px; }
.checkbox-label { display: flex; align-items: center; cursor: pointer; }
.checkbox-label input[type="checkbox"] { width: auto; margin-right: 8px; }

/* 通知样式 */
#notification-area { margin-bottom: 15px; }
.notification { padding: 10px; margin-bottom: 10px; border-radius: 4px; }
.notification.success { background-color: #d4edda; color: #155724; }
.notification.error { background-color: #f8d7da; color: #721c24; }
.notification.info { background-color: #d1ecf1; color: #0c5460; }

/* 确认对话框样式 */
#confirm-dialog { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 200; }
.dialog-content { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 20px; border-radius: 8px; width: 80%; max-width: 400px; }
.dialog-buttons { display: flex; justify-content: flex-end; margin-top: 20px; }
.dialog-buttons button { margin-left: 10px; }
#confirm-yes { background: #dc3545; }
#confirm-no { background: #6c757d; }

/* 响应式设计 */
@media (max-width: 768px) {
  table { display: block; overflow-x: auto; }
  .form-group { margin-bottom: 10px; }
}
  `,

  // 管理后台JavaScript脚本
  adminScripts: `
/**
 * 管理后台应用类
 */
class AdminApp {
  /**
   * 构造函数
   * @param {Object} config - 配置对象 
   */
  constructor(config) {
    this.routes = config.routes || [];
    this.csrfToken = config.csrfToken || '';
    this.currentActionCallback = null;
  }

  /**
   * 初始化应用
   */
  init() {
    this.bindEvents();
    this.setupCSRFForFetch();
  }

  /**
   * 绑定事件处理器
   */
  bindEvents() {
    // 常规按钮事件
    document.getElementById('add-rule-btn').addEventListener('click', () => this.showAddForm());
    document.getElementById('cancel-btn').addEventListener('click', () => this.hideForm());
    document.getElementById('route-form').addEventListener('submit', (e) => this.handleFormSubmit(e));
    document.getElementById('type').addEventListener('change', () => this.toggleTypeFields());
    
    // 退出登录
    document.getElementById('logout-btn').addEventListener('click', () => 
      this.confirmAction('退出登录', '确定要退出登录吗？', () => this.logout()));
    
    // 确认对话框按钮
    document.getElementById('confirm-yes').addEventListener('click', () => {
      if (typeof this.currentActionCallback === 'function') {
        this.currentActionCallback();
      }
      this.hideConfirmDialog();
    });
    document.getElementById('confirm-no').addEventListener('click', () => this.hideConfirmDialog());
    
    // 路由操作按钮
    this.bindRouteButtons();
  }
  
  /**
   * 绑定路由相关按钮事件
   */
  bindRouteButtons() {
    // 编辑按钮
    document.querySelectorAll('.edit-btn').forEach(btn => {
      btn.addEventListener('click', () => this.editRoute(parseInt(btn.dataset.index)));
    });
    
    // 删除按钮
    document.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const index = parseInt(btn.dataset.index);
        this.confirmAction(
          '删除规则',
          \`确定要删除路径为 "\${this.routes[index].path}" 的规则吗？\`,
          () => this.deleteRoute(index)
        );
      });
    });
    
    // 启用/禁用按钮
    document.querySelectorAll('.toggle-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const index = parseInt(btn.dataset.index);
        const enabled = btn.dataset.enabled === 'true';
        const action = enabled ? '禁用' : '启用';
        this.confirmAction(
          \`\${action}规则\`,
          \`确定要\${action}路径为 "\${this.routes[index].path}" 的规则吗？\`,
          () => this.toggleRoute(index)
        );
      });
    });
  }
  
  /**
   * 设置Fetch请求的CSRF保护
   */
  setupCSRFForFetch() {
    const originalFetch = window.fetch;
    
    window.fetch = (url, options = {}) => {
      // 只对POST请求添加CSRF令牌
      if (options.method && options.method.toUpperCase() === 'POST') {
        options.headers = options.headers || {};
        
        // 设置CSRF头
        options.headers['X-CSRF-Token'] = this.csrfToken;
        
        // 如果是JSON请求，尝试在body中也添加CSRF令牌
        if (options.headers['Content-Type'] === 'application/json') {
          try {
            let body = JSON.parse(options.body);
            body.csrf_token = this.csrfToken;
            options.body = JSON.stringify(body);
          } catch (e) {
            console.error('无法解析JSON body添加CSRF令牌', e);
          }
        }
      }
      
      return originalFetch(url, options);
    };
  }

  /**
   * 显示添加表单
   */
  showAddForm() {
    document.getElementById('form-title').textContent = '添加规则';
    document.getElementById('route-form').reset();
    document.getElementById('route-index').value = '';
    document.getElementById('path').value = '/';
    document.getElementById('overlay').style.display = 'block';
    document.getElementById('form-container').style.display = 'block';
    this.toggleTypeFields();
  }

  /**
   * 编辑路由
   * @param {Number} index - 路由索引
   */
  editRoute(index) {
    const route = this.routes[index];
    document.getElementById('form-title').textContent = '编辑规则';
    document.getElementById('route-index').value = index;
    document.getElementById('path').value = route.path;
    document.getElementById('type').value = route.type;
    document.getElementById('target').value = route.type === 'redirect' ? route.target : '';
    document.getElementById('remark').value = route.remark || '';
    document.getElementById('enabled').checked = route.enabled;
    
    // 获取内容（如果是自定义内容类型）
    if (route.type === 'content' && route.content_key) {
      this.fetchWithErrorHandling('/admin/content?key=' + encodeURIComponent(route.content_key))
        .then(content => {
          document.getElementById('content').value = content;
        });
    } else {
      document.getElementById('content').value = '';
    }
    
    document.getElementById('overlay').style.display = 'block';
    document.getElementById('form-container').style.display = 'block';
    this.toggleTypeFields();
  }

  /**
   * 隐藏表单
   */
  hideForm() {
    document.getElementById('overlay').style.display = 'none';
    document.getElementById('form-container').style.display = 'none';
  }

  /**
   * 切换类型字段显示
   */
  toggleTypeFields() {
    const type = document.getElementById('type').value;
    document.getElementById('target-group').style.display = type === 'redirect' ? 'block' : 'none';
    document.getElementById('content-group').style.display = type === 'content' ? 'block' : 'none';
  }

  /**
   * 处理表单提交
   * @param {Event} e - 事件对象
   */
  handleFormSubmit(e) {
    e.preventDefault();
    const index = document.getElementById('route-index').value;
    const formData = {
      path: document.getElementById('path').value,
      type: document.getElementById('type').value,
      target: document.getElementById('target').value,
      content: document.getElementById('content').value,
      remark: document.getElementById('remark').value,
      enabled: document.getElementById('enabled').checked,
      csrf_token: this.csrfToken
    };
    
    // 验证必填字段
    if (!formData.path) {
      return this.showNotification('路径不能为空', 'error');
    }
    
    if (formData.type === 'redirect' && !formData.target) {
      return this.showNotification('重定向目标不能为空', 'error');
    }
    
    if (formData.type === 'content' && !formData.content) {
      return this.showNotification('自定义内容不能为空', 'error');
    }
    
    // 提交表单
    const isAdd = index === '';
    const url = isAdd ? '/admin/add' : '/admin/update';
    const requestData = {
      index: isAdd ? null : parseInt(index),
      route: formData
    };
    
    this.fetchWithErrorHandling(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestData)
    })
    .then(data => {
      this.hideForm();
      this.showNotification(isAdd ? '规则添加成功' : '规则更新成功', 'success');
      
      if (isAdd) {
        // 如果是添加操作，刷新页面获取新数据
        window.location.reload();
      } else {
        // 如果是编辑操作，更新本地数据和表格行
        this.routes[index] = data.route;
        this.updateTableRow(index, data.route);
      }
    });
  }

  /**
   * 删除路由
   * @param {Number} index - 路由索引
   */
  deleteRoute(index) {
    this.fetchWithErrorHandling('/admin/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ index, csrf_token: this.csrfToken })
    })
    .then(() => {
      // 从DOM中移除行
      const row = document.getElementById(\`route-row-\${index}\`);
      if (row) row.remove();
      
      // 从数据中移除
      this.routes.splice(index, 1);
      this.showNotification('规则已删除', 'success');
    });
  }

  /**
   * 切换路由启用状态
   * @param {Number} index - 路由索引
   */
  toggleRoute(index) {
    this.fetchWithErrorHandling('/admin/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ index, csrf_token: this.csrfToken })
    })
    .then(data => {
      // 更新本地数据
      this.routes[index].enabled = data.enabled;
      
      // 更新UI
      const statusCell = document.getElementById(\`route-status-\${index}\`);
      const toggleBtn = document.querySelector(\`.toggle-btn[data-index="\${index}"]\`);
      
      if (statusCell) statusCell.textContent = data.enabled ? '启用' : '禁用';
      
      if (toggleBtn) {
        toggleBtn.textContent = data.enabled ? '禁用' : '启用';
        toggleBtn.dataset.enabled = data.enabled;
      }
      
      this.showNotification(\`规则已\${data.enabled ? '启用' : '禁用'}\`, 'success');
    });
  }

  /**
   * 退出登录
   */
  logout() {
    try {
      // 尝试使用API
      this.fetchWithErrorHandling('/admin/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csrf_token: this.csrfToken })
      })
      .then(() => {
        document.cookie = 'auth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        window.location.href = '/admin';
      })
      .catch(() => {
        // 如果API调用失败，回退到直接清除cookie
        document.cookie = 'auth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        window.location.href = '/admin';
      });
    } catch (error) {
      // 异常情况直接清除cookie
      document.cookie = 'auth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      window.location.href = '/admin';
    }
  }

  /**
   * 显示确认对话框
   * @param {String} title - 对话框标题
   * @param {String} message - 确认消息
   * @param {Function} callback - 确认后的回调函数
   */
  confirmAction(title, message, callback) {
    document.getElementById('confirm-title').textContent = title;
    document.getElementById('confirm-message').textContent = message;
    this.currentActionCallback = callback;
    document.getElementById('confirm-dialog').style.display = 'block';
  }

  /**
   * 隐藏确认对话框
   */
  hideConfirmDialog() {
    document.getElementById('confirm-dialog').style.display = 'none';
    this.currentActionCallback = null;
  }

  /**
   * 显示通知
   * @param {String} message - 通知消息
   * @param {String} type - 通知类型 (success, error, info)
   * @param {Number} duration - 持续时间(毫秒)
   */
  showNotification(message, type = 'info', duration = 3000) {
    const notificationArea = document.getElementById('notification-area');
    const notification = document.createElement('div');
    notification.className = \`notification \${type}\`;
    notification.textContent = message;
    
    notificationArea.appendChild(notification);
    
    // 自动移除通知
    setTimeout(() => {
      notification.style.opacity = '0';
      notification.style.transition = 'opacity 0.5s';
      setTimeout(() => notification.remove(), 500);
    }, duration);
  }

  /**
   * 更新表格行
   * @param {Number} index - 路由索引
   * @param {Object} route - 更新后的路由数据
   */
  updateTableRow(index, route) {
    const row = document.getElementById(\`route-row-\${index}\`);
    if (!row) return;
    
    const cells = row.getElementsByTagName('td');
    cells[0].textContent = route.path;
    cells[1].textContent = route.type === 'redirect' ? '重定向' : '自定义内容';
    cells[2].textContent = route.type === 'redirect' ? route.target : '已存储内容';
    cells[3].textContent = route.remark || '-';
    cells[4].textContent = route.enabled ? '启用' : '禁用';
    
    // 更新按钮状态
    const toggleBtn = row.querySelector('.toggle-btn');
    if (toggleBtn) {
      toggleBtn.textContent = route.enabled ? '禁用' : '启用';
      toggleBtn.dataset.enabled = route.enabled;
    }
  }

  /**
   * 带错误处理的Fetch
   * @param {String} url - 请求URL
   * @param {Object} options - 请求选项
   * @returns {Promise} - 请求Promise
   */
  fetchWithErrorHandling(url, options = {}) {
    return fetch(url, options)
      .then(response => {
        if (!response.ok) {
          return response.text().then(text => {
            try {
              // 尝试解析JSON错误
              const error = JSON.parse(text);
              throw new Error(error.message || \`请求失败: \${response.status}\`);
            } catch (e) {
              // 如果不是JSON，使用原始错误文本
              throw new Error(text || \`请求失败: \${response.status}\`);
            }
          });
        }
        
        // 检查内容类型
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          return response.json();
        }
        
        return response.text();
      })
      .catch(error => {
        this.showNotification(error.message || '请求发生错误', 'error');
        throw error;
      });
  }
}
  `,

  // 404页面 (仿Nginx样式)
  notFound: `
<!DOCTYPE html>
<html>
<head>
<title>404 Not Found</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>404 Not Found</h1>
<p>The requested resource could not be found on this server.</p>
<hr>
<p><em>nginx</em></p>
</body>
</html>
  `,

  // 根目录页面 (仿Nginx样式)
  index: `
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
  `
};

/**
 * 工具函数集合
 */
// HTML转义函数
function escapeHTML(str) {
  if (!str) return '';
  return str.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 设置安全响应头
function setSecurityHeaders(headers = {}, includeTurnstile = false) {
  // 基础 CSP 指令
  const cspDirectives = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'"
  ];
  
  // 如果需要 Turnstile，添加相关域名
  if (includeTurnstile) {
    cspDirectives[1] += " https://challenges.cloudflare.com";
    cspDirectives[4] += " https://challenges.cloudflare.com";
    // 添加 frame-src 指令
    cspDirectives.push("frame-src 'self' https://challenges.cloudflare.com");
  }
  
  return {
    ...headers,
    'Content-Security-Policy': cspDirectives.join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  };
}

// 设置缓存响应头
function setCacheHeaders(headers = {}, maxAge = 3600) {
  return {
    ...headers,
    'Cache-Control': `public, max-age=${maxAge}`,
    'ETag': Date.now().toString(36)
  };
}

// 创建JSON响应
function createJsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: setSecurityHeaders({
      'Content-Type': 'application/json',
      ...headers
    })
  });
}

// 创建错误响应
function createErrorResponse(message, status = 400) {
  return createJsonResponse({ error: true, message }, status);
}

/**
 * 加密/解密工具类
 */
class CryptoUtil {
  /**
   * 生成随机字符串
   * @param {number} length - 长度
   * @returns {string} - 随机字符串
   */
  static generateRandomString(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * 计算HMAC签名
   * @param {string} message - 要签名的消息
   * @param {string} key - HMAC密钥
   * @returns {Promise<string>} - 签名结果
   */
  static async hmacSign(message, key) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const messageData = encoder.encode(message);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      messageData
    );
    
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * 验证HMAC签名
   * @param {string} message - 原始消息
   * @param {string} signature - 签名
   * @param {string} key - HMAC密钥
   * @returns {Promise<boolean>} - 验证结果
   */
  static async hmacVerify(message, signature, key) {
    const calculatedSignature = await this.hmacSign(message, key);
    return calculatedSignature === signature;
  }
  
  /**
   * 生成内容的哈希值作为ETag
   * @param {string} content - 内容
   * @returns {Promise<string>} - 哈希值
   */
  static async generateETag(content) {
    const encoder = new TextEncoder();
    const contentData = encoder.encode(content);
    
    const hashBuffer = await crypto.subtle.digest('SHA-1', contentData);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

/**
 * 管理会话认证的类
 */
class AuthManager {
  /**
   * 构造函数
   * @param {Request} request - 请求对象
   * @param {string} hmacKey - HMAC密钥
   */
  constructor(request, hmacKey) {
    this.request = request;
    this.hmacKey = hmacKey;
    this.cookies = this.parseCookies();
  }

  /**
   * 解析请求中的Cookie
   * @returns {Object} - Cookie键值对
   */
  parseCookies() {
    const cookies = {};
    const cookieHeader = this.request.headers.get('Cookie') || '';
    
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name) cookies[name] = value;
    });
    
    return cookies;
  }

  /**
   * 创建认证Cookie
   * @returns {Promise<string>} - 设置Cookie的头信息
   */
  async createAuthCookie() {
    const timestamp = Date.now();
    const sessionId = CryptoUtil.generateRandomString(32);
    const payload = `${sessionId}|${timestamp}`;
    const signature = await CryptoUtil.hmacSign(payload, this.hmacKey);
    
    return `auth=${payload}:${signature}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict; Secure`;
  }
  
  /**
   * 创建用于删除认证Cookie的头信息
   * @returns {string} - 删除Cookie的头信息
   */
  createLogoutCookie() {
    return 'auth=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Strict; Secure';
  }

  /**
   * 验证认证Cookie
   * @returns {Promise<boolean>} - 验证结果
   */
  async verifyAuth() {
    const authCookie = this.cookies.auth;
    if (!authCookie) return false;
    
    const [payload, signature] = authCookie.split(':');
    if (!payload || !signature) return false;
    
    const [sessionId, timestamp] = payload.split('|');
    if (!sessionId || !timestamp) return false;
    
    // 检查会话是否过期 (24小时)
    const cookieTime = parseInt(timestamp);
    if (isNaN(cookieTime) || Date.now() - cookieTime > 24 * 60 * 60 * 1000) {
      return false;
    }
    
    // 验证签名
    return CryptoUtil.hmacVerify(payload, signature, this.hmacKey);
  }
  
  /**
   * 创建CSRF令牌Cookie
   * @param {string} token - CSRF令牌
   * @returns {string} - 设置Cookie的头信息
   */
  createCsrfCookie(token) {
    return `csrf=${token}; Path=/; Max-Age=86400; SameSite=Strict; Secure`;
  }
}

/**
 * 处理Turnstile验证码的类
 */
class TurnstileValidator {
  /**
   * 构造函数
   * @param {string} secretKey - Turnstile密钥
   */
  constructor(secretKey) {
    this.secretKey = secretKey;
  }
  
  /**
   * 验证Turnstile令牌
   * @param {string} token - 客户端令牌
   * @param {string} ip - 客户端IP
   * @returns {Promise<boolean>} - 验证结果
   */
  async verify(token, ip) {
    if (!token) return false;
    
    try {
      const formData = new FormData();
      formData.append('secret', this.secretKey);
      formData.append('response', token);
      formData.append('remoteip', ip);
      
      const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        body: formData
      });
      
      const data = await response.json();
      return data.success === true;
    } catch (error) {
      console.error('Turnstile verification error:', error);
      return false;
    }
  }
}

/**
 * 路由配置管理类
 */
class RouteManager {
  /**
   * 构造函数
   * @param {KVNamespace} kv - KV存储命名空间
   */
  constructor(kv) {
    this.kv = kv;
    this.cacheVersion = Date.now().toString(36); // 用于缓存版本控制
  }
  
  /**
   * 获取所有路由配置
   * @returns {Promise<Object>} - 配置对象
   */
  async getConfig() {
    let config = await this.kv.get('config', 'json');
    if (!config) {
      config = { routes: [] };
      await this.saveConfig(config);
    }
    return config;
  }
  
  /**
   * 保存配置
   * @param {Object} config - 配置对象
   * @returns {Promise<void>}
   */
  async saveConfig(config) {
    await this.kv.put('config', JSON.stringify(config));
    // 更新缓存版本
    this.cacheVersion = Date.now().toString(36);
    // 存储缓存版本号到KV
    await this.kv.put('cache_version', this.cacheVersion);
  }
  
  /**
   * 获取缓存版本号
   * @returns {Promise<string>} - 缓存版本号
   */
  async getCacheVersion() {
    const version = await this.kv.get('cache_version');
    return version || this.cacheVersion;
  }
  
  /**
   * 根据路径查找路由
   * @param {string} path - 请求路径
   * @returns {Promise<Object|null>} - 找到的路由或null
   */
  async findRoute(path) {
    const config = await this.getConfig();
    return config.routes.find(route => route.path === path && route.enabled);
  }
  
  /**
   * 处理内容类型路由的内容
   * @param {Object} route - 路由对象
   * @returns {Promise<Object>} - 处理后的路由对象 
   */
  async processContentRoute(route) {
    if (route.type !== 'content') return route;
    
    // 生成内容键
    route.content_key = `content_${route.path.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
    
    // 存储内容
    await this.kv.put(route.content_key, route.content);
    
    // 生成内容哈希作为ETag
    route.etag = await CryptoUtil.generateETag(route.content);
    
    // 从路由对象中删除内容
    delete route.content;
    
    return route;
  }
  
  /**
   * 添加新路由
   * @param {Object} route - 路由对象
   * @returns {Promise<Object>} - 处理结果
   */
  async addRoute(route) {
    const config = await this.getConfig();
    
    // 检查路径是否已存在
    if (config.routes.some(r => r.path === route.path)) {
      throw new Error(`路径 "${route.path}" 已存在`);
    }
    
    // 处理内容类型
    route = await this.processContentRoute(route);
    
    // 添加到配置
    config.routes.push(route);
    await this.saveConfig(config);
    
    return { success: true, route };
  }
  
  /**
   * 更新路由
   * @param {number} index - 路由索引
   * @param {Object} route - 更新的路由对象
   * @returns {Promise<Object>} - 处理结果
   */
  async updateRoute(index, route) {
    const config = await this.getConfig();
    
    // 检查索引是否有效
    if (index < 0 || index >= config.routes.length) {
      throw new Error('无效的路由索引');
    }
    
    const oldRoute = config.routes[index];
    
    // 检查路径是否已存在(排除自身)
    if (route.path !== oldRoute.path && config.routes.some(r => r.path === route.path)) {
      throw new Error(`路径 "${route.path}" 已存在`);
    }
    
    // 处理内容类型
    if (route.type === 'content') {
      // 检查内容是否已更改
      let contentChanged = true;
      
      if (oldRoute.type === 'content' && oldRoute.content_key) {
        const oldContent = await this.kv.get(oldRoute.content_key);
        if (oldContent === route.content) {
          contentChanged = false;
          route.content_key = oldRoute.content_key;
          route.etag = oldRoute.etag;
        }
      }
      
      if (contentChanged) {
        // 内容已更改或类型从redirect改为content
        const contentKey = `content_${route.path.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
        
        // 存储内容
        await this.kv.put(contentKey, route.content);
        
        // 生成ETag
        route.etag = await CryptoUtil.generateETag(route.content);
        
        // 更新内容键
        route.content_key = contentKey;
      }
      
      // 从路由对象中删除内容
      delete route.content;
    } else if (oldRoute.type === 'content' && route.type === 'redirect') {
      // 如果类型从content改为redirect，保留content_key以防需要切换回来
      route.content_key = oldRoute.content_key;
      route.etag = oldRoute.etag;
    }
    
    // 更新配置
    config.routes[index] = route;
    await this.saveConfig(config);
    
    return { success: true, route };
  }
  
  /**
   * 删除路由
   * @param {number} index - 路由索引
   * @returns {Promise<Object>} - 处理结果
   */
  async deleteRoute(index) {
    const config = await this.getConfig();
    
    // 检查索引是否有效
    if (index < 0 || index >= config.routes.length) {
      throw new Error('无效的路由索引');
    }
    
    const route = config.routes[index];
    
    // 如果是内容类型，删除关联内容
    if (route.type === 'content' && route.content_key) {
      try {
        await this.kv.delete(route.content_key);
      } catch (error) {
        console.error('删除内容时出错:', error);
        // 继续删除路由，即使内容删除失败
      }
    }
    
    // 从配置中删除
    config.routes.splice(index, 1);
    await this.saveConfig(config);
    
    return { success: true };
  }
  
  /**
   * 切换路由启用状态
   * @param {number} index - 路由索引
   * @returns {Promise<Object>} - 处理结果
   */
  async toggleRoute(index) {
    const config = await this.getConfig();
    
    // 检查索引是否有效
    if (index < 0 || index >= config.routes.length) {
      throw new Error('无效的路由索引');
    }
    
    // 切换状态
    config.routes[index].enabled = !config.routes[index].enabled;
    await this.saveConfig(config);
    
    return { 
      success: true, 
      enabled: config.routes[index].enabled 
    };
  }
  
  /**
   * 获取路由内容
   * @param {string} key - 内容键
   * @returns {Promise<string>} - 内容
   */
  async getContent(key) {
    const content = await this.kv.get(key);
    if (!content) {
      throw new Error('内容不存在');
    }
    return content;
  }
}

/**
 * 管理后台控制器
 */
class AdminController {
  /**
   * 构造函数
   * @param {Request} request - 请求对象
   * @param {RouteManager} routeManager - 路由管理器
   * @param {AuthManager} authManager - 认证管理器
   * @param {Object} env - 环境变量
   */
  constructor(request, routeManager, authManager, env) {
    this.request = request;
    this.routeManager = routeManager;
    this.authManager = authManager;
    this.env = env;
    this.url = new URL(request.url);
    this.path = this.url.pathname;
    this.csrfToken = '';
  }
  
  /**
   * 处理请求
   * @returns {Promise<Response>} - 响应
   */
  async handleRequest() {
    // 检查是否是资源请求
    if (this.path === '/admin/styles.css') {
      return new Response(TEMPLATES.adminStyles, {
        headers: setSecurityHeaders({
          'Content-Type': 'text/css',
          // 管理界面资源可以缓存较长时间
          'Cache-Control': 'public, max-age=86400'
        })
      });
    }
    
    if (this.path === '/admin/scripts.js') {
      return new Response(TEMPLATES.adminScripts, {
        headers: setSecurityHeaders({
          'Content-Type': 'application/javascript',
          // 管理界面资源可以缓存较长时间
          'Cache-Control': 'public, max-age=86400'
        })
      });
    }
    
    // 检查认证
    const isAuthenticated = await this.authManager.verifyAuth();
    
    // 处理退出登录
    if (this.path === '/admin/logout' && this.request.method === 'POST') {
      return this.handleLogout();
    }
    
    // 登录处理
    if (this.path === '/admin' || this.path === '/admin/') {
      if (isAuthenticated) {
        return this.showAdminPanel();
      } else {
        return this.handleLogin();
      }
    }
    
    // 所有其他管理请求都需要认证
    if (!isAuthenticated) {
      return new Response('Unauthorized', { status: 401 });
    }
    
    // 处理不同的管理请求
    const handlers = {
      '/admin/add': this.handleAddRoute.bind(this),
      '/admin/update': this.handleUpdateRoute.bind(this),
      '/admin/delete': this.handleDeleteRoute.bind(this),
      '/admin/toggle': this.handleToggleRoute.bind(this),
      '/admin/content': this.handleGetContent.bind(this)
    };
    
    const handler = handlers[this.path];
    if (handler) {
      return handler();
    }
    
    // 默认返回404
    return new Response('Not Found', { status: 404 });
  }
  
  /**
   * 生成CSRF令牌
   * @returns {string} - CSRF令牌
   */
  generateCsrfToken() {
    this.csrfToken = CryptoUtil.generateRandomString(32);
    return this.csrfToken;
  }
  
  /**
   * 验证CSRF令牌
   * @param {Object} data - 请求数据
   * @returns {Promise<boolean>} - 验证结果
   */
  async validateCsrfToken(data) {
    const tokenFromHeader = this.request.headers.get('X-CSRF-Token');
    const tokenFromBody = data?.csrf_token;
    const tokenFromCookie = this.authManager.cookies.csrf;
    
    // 如果有Cookie令牌，检查是否匹配
    if (tokenFromCookie) {
      return tokenFromHeader === tokenFromCookie || tokenFromBody === tokenFromCookie;
    }
    
    // 降级：如果没有Cookie但有一致的头和体令牌
    return tokenFromHeader && tokenFromBody && tokenFromHeader === tokenFromBody;
  }
  
  /**
   * 显示管理面板
   * @returns {Promise<Response>} - 响应
   */
  async showAdminPanel() {
    const config = await this.routeManager.getConfig();
    const csrfToken = this.generateCsrfToken();
    
    const headers = setSecurityHeaders({
      'Content-Type': 'text/html',
      'Set-Cookie': this.authManager.createCsrfCookie(csrfToken),
      // 管理面板不缓存
      'Cache-Control': 'no-store, must-revalidate'
    });
    
    return new Response(TEMPLATES.admin(config.routes, csrfToken), { headers });
  }
  
  /**
   * 处理登录
   * @returns {Promise<Response>} - 响应
   */
  async handleLogin() {
    // 处理登录表单提交
    if (this.request.method === 'POST') {
      const formData = await this.request.formData();
      const password = formData.get('password');
      const turnstileResponse = formData.get('cf-turnstile-response');
      
      // 验证Turnstile
      const clientIp = this.request.headers.get('CF-Connecting-IP');
      const turnstileValidator = new TurnstileValidator(this.env.TURNSTILE_SECRET_KEY);
      const turnstileValid = await turnstileValidator.verify(turnstileResponse, clientIp);
      
      if (!turnstileValid) {
        const csrfToken = this.generateCsrfToken();
        const headers = setSecurityHeaders({
          'Content-Type': 'text/html',
          'Set-Cookie': this.authManager.createCsrfCookie(csrfToken),
          'Cache-Control': 'no-store, must-revalidate'
        }, true);
        
        return new Response(
          TEMPLATES.login(this.env.TURNSTILE_SITE_KEY, '请完成人机验证', csrfToken),
          { headers }
        );
      }
      
      // 验证密码
      if (password === this.env.ADMIN_PASSWORD) {
        // 创建认证Cookie
        const authCookie = await this.authManager.createAuthCookie();
        const csrfToken = this.generateCsrfToken();
        const csrfCookie = this.authManager.createCsrfCookie(csrfToken);
        
        // 重定向到管理面板
        return new Response('Login successful, redirecting...', {
          status: 302,
          headers: setSecurityHeaders({
            'Location': '/admin',
            'Set-Cookie': [authCookie, csrfCookie],
            'Cache-Control': 'no-store, must-revalidate'
          })
        });
      } else {
        const csrfToken = this.generateCsrfToken();
        const headers = setSecurityHeaders({
          'Content-Type': 'text/html',
          'Set-Cookie': this.authManager.createCsrfCookie(csrfToken),
          'Cache-Control': 'no-store, must-revalidate'
        }, true);
        
        return new Response(
          TEMPLATES.login(this.env.TURNSTILE_SITE_KEY, '密码错误', csrfToken),
          { headers }
        );
      }
    }
    
    // 显示登录表单
    const csrfToken = this.generateCsrfToken();
    const headers = setSecurityHeaders({
      'Content-Type': 'text/html',
      'Set-Cookie': this.authManager.createCsrfCookie(csrfToken),
      'Cache-Control': 'no-store, must-revalidate'
    }, true);
    
    return new Response(
      TEMPLATES.login(this.env.TURNSTILE_SITE_KEY, '', csrfToken),
      { headers }
    );
  }
  
  /**
   * 处理退出登录
   * @returns {Promise<Response>} - 响应
   */
  async handleLogout() {
    try {
      const data = await this.request.json();
      
      // 验证CSRF令牌
      if (!await this.validateCsrfToken(data)) {
        return createErrorResponse('CSRF验证失败', 403);
      }
      
      // 设置删除Cookie的头
      const logoutCookie = this.authManager.createLogoutCookie();
      
      return createJsonResponse(
        { success: true, message: '已成功退出登录' },
        200,
        { 
          'Set-Cookie': logoutCookie,
          'Cache-Control': 'no-store, must-revalidate'
        }
      );
    } catch (error) {
      return createErrorResponse('退出失败: ' + error.message, 500);
    }
  }
  
  /**
   * 处理添加路由
   * @returns {Promise<Response>} - 响应
   */
  async handleAddRoute() {
    if (this.request.method !== 'POST') {
      return createErrorResponse('Method Not Allowed', 405);
    }
    
    try {
      const data = await this.request.json();
      
      // 验证CSRF令牌
      if (!await this.validateCsrfToken(data)) {
        return createErrorResponse('CSRF验证失败', 403);
      }
      
      const route = data.route;
      
      // 基本验证
      if (!route || !route.path || !route.type) {
        return createErrorResponse('缺少必要参数');
      }
      
      // 类型验证
      if (route.type === 'redirect' && !route.target) {
        return createErrorResponse('重定向类型必须提供目标URL');
      }
      
      if (route.type === 'content' && !route.content) {
        return createErrorResponse('内容类型必须提供内容');
      }
      
      const result = await this.routeManager.addRoute(route);
      return createJsonResponse(result);
    } catch (error) {
      return createErrorResponse(error.message);
    }
  }
  
  /**
   * 处理更新路由
   * @returns {Promise<Response>} - 响应
   */
  async handleUpdateRoute() {
    if (this.request.method !== 'POST') {
      return createErrorResponse('Method Not Allowed', 405);
    }
    
    try {
      const data = await this.request.json();
      
      // 验证CSRF令牌
      if (!await this.validateCsrfToken(data)) {
        return createErrorResponse('CSRF验证失败', 403);
      }
      
      const index = data.index;
      const route = data.route;
      
      // 基本验证
      if (index === undefined || !route || !route.path || !route.type) {
        return createErrorResponse('缺少必要参数');
      }
      
      // 类型验证
      if (route.type === 'redirect' && !route.target) {
        return createErrorResponse('重定向类型必须提供目标URL');
      }
      
      if (route.type === 'content' && !route.content) {
        return createErrorResponse('内容类型必须提供内容');
      }
      
      const result = await this.routeManager.updateRoute(index, route);
      return createJsonResponse(result);
    } catch (error) {
      return createErrorResponse(error.message);
    }
  }
  
  /**
   * 处理删除路由
   * @returns {Promise<Response>} - 响应
   */
  async handleDeleteRoute() {
    if (this.request.method !== 'POST') {
      return createErrorResponse('Method Not Allowed', 405);
    }
    
    try {
      const data = await this.request.json();
      
      // 验证CSRF令牌
      if (!await this.validateCsrfToken(data)) {
        return createErrorResponse('CSRF验证失败', 403);
      }
      
      const index = data.index;
      
      // 基本验证
      if (index === undefined) {
        return createErrorResponse('缺少必要参数');
      }
      
      const result = await this.routeManager.deleteRoute(index);
      return createJsonResponse(result);
    } catch (error) {
      return createErrorResponse(error.message);
    }
  }
  
  /**
   * 处理切换路由启用状态
   * @returns {Promise<Response>} - 响应
   */
   async handleToggleRoute() {
    if (this.request.method !== 'POST') {
      return createErrorResponse('Method Not Allowed', 405);
    }
    
    try {
      const data = await this.request.json();
      
      // 验证CSRF令牌
      if (!await this.validateCsrfToken(data)) {
        return createErrorResponse('CSRF验证失败', 403);
      }
      
      const index = data.index;
      
      // 基本验证
      if (index === undefined) {
        return createErrorResponse('缺少必要参数');
      }
      
      const result = await this.routeManager.toggleRoute(index);
      return createJsonResponse(result);
    } catch (error) {
      return createErrorResponse(error.message);
    }
  }
  
  /**
   * 处理获取内容
   * @returns {Promise<Response>} - 响应
   */
  async handleGetContent() {
    try {
      const key = this.url.searchParams.get('key');
      
      // 基本验证
      if (!key) {
        return createErrorResponse('缺少必要参数');
      }
      
      const content = await this.routeManager.getContent(key);
      return new Response(content, {
        headers: setSecurityHeaders({ 
          'Content-Type': 'text/plain',
          'Cache-Control': 'no-store, must-revalidate' // 内容不缓存
        })
      });
    } catch (error) {
      return createErrorResponse(error.message);
    }
  }
}

/**
 * 主应用类
 */
class GatewayApp {
  /**
   * 构造函数
   * @param {Request} request - 请求对象
   * @param {Object} env - 环境变量
   * @param {Object} ctx - 执行上下文
   */
  constructor(request, env, ctx) {
    this.request = request;
    this.env = env;
    this.ctx = ctx;
    this.url = new URL(request.url);
    this.path = this.url.pathname;
    this.routeManager = new RouteManager(env.GATEWAY);
    this.authManager = new AuthManager(request, env.HMAC_KEY);
  }
  
  /**
   * 处理请求
   * @returns {Promise<Response>} - 响应
   */
  async handleRequest() {
    // 处理管理请求
    if (this.path === '/admin' || this.path.startsWith('/admin/')) {
      const adminController = new AdminController(
        this.request, 
        this.routeManager, 
        this.authManager, 
        this.env
      );
      return adminController.handleRequest();
    }
    
    // 检查缓存控制
    const ifNoneMatch = this.request.headers.get('If-None-Match');
    const cacheVersion = await this.routeManager.getCacheVersion();
    
    // 处理根路径
    if (this.path === '/') {
      // 生成ETag和缓存控制
      const etag = `W/"index-${cacheVersion}"`;
      
      // 如果客户端提供了匹配的ETag，返回304未修改
      if (ifNoneMatch && ifNoneMatch === etag) {
        return new Response(null, {
          status: 304,
          headers: {
            'ETag': etag,
            'Cache-Control': 'public, max-age=3600'
          }
        });
      }
      
      return new Response(TEMPLATES.index, {
        headers: setSecurityHeaders({ 
          'Content-Type': 'text/html',
          'ETag': etag,
          'Cache-Control': 'public, max-age=3600'
        })
      });
    }
    
    // 查找路由
    const route = await this.routeManager.findRoute(this.path);
    
    if (route) {
      if (route.type === 'redirect') {
        return Response.redirect(route.target, 302);
      } else if (route.type === 'content' && route.content_key) {
        const content = await this.routeManager.getContent(route.content_key);
        
        // 基于内容类型设置Content-Type
        const contentType = content.trim().startsWith('<!DOCTYPE html>') || 
                           content.trim().startsWith('<html') ? 
                           'text/html' : 'text/plain; charset=utf-8';
        
        // 使用保存的ETag或生成新的
        const etag = route.etag || await CryptoUtil.generateETag(content);
        
        // 如果客户端提供了匹配的ETag，返回304未修改
        if (ifNoneMatch && ifNoneMatch === etag) {
          return new Response(null, {
            status: 304,
            headers: {
              'ETag': etag,
              'Cache-Control': 'public, max-age=3600',
              'X-Cache-Version': cacheVersion
            }
          });
        }
        
        return new Response(content, {
          headers: setSecurityHeaders({ 
            'Content-Type': contentType,
            'ETag': etag,
            'Cache-Control': 'public, max-age=3600',
            'X-Cache-Version': cacheVersion
          })
        });
      }
    }
    
    // 默认返回404
    // 404页面也进行缓存控制
    const notFoundEtag = `W/"404-${cacheVersion}"`;
    
    // 如果客户端提供了匹配的ETag，返回304未修改
    if (ifNoneMatch && ifNoneMatch === notFoundEtag) {
      return new Response(null, {
        status: 304,
        headers: {
          'ETag': notFoundEtag,
          'Cache-Control': 'public, max-age=60' // 404页面缓存时间较短
        }
      });
    }
    
    return new Response(TEMPLATES.notFound, {
      status: 404,
      headers: setSecurityHeaders({ 
        'Content-Type': 'text/html',
        'ETag': notFoundEtag,
        'Cache-Control': 'public, max-age=60' // 404页面缓存时间较短
      })
    });
  }
}

// Workers入口点
export default {
  /**
   * 请求处理函数
   * @param {Request} request - 请求对象
   * @param {Object} env - 环境变量
   * @param {Object} ctx - 执行上下文
   * @returns {Promise<Response>} - 响应
   */
  async fetch(request, env, ctx) {
    const app = new GatewayApp(request, env, ctx);
    
    try {
      return await app.handleRequest();
    } catch (error) {
      console.error('应用错误:', error);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};
