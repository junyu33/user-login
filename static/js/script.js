function register() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;
  const captcha = document.getElementById('captcha').value;

  let passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*?[#?!@$%^&*-]).{8,}$/;
  if (!passwordRegex.test(password)) {
    alert('密码包括大小写字母，数字和特殊字符，8位以上');
    return;
  }

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(user + '.' + password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword, captcha }; // Include the user and hashed password
      fetch('/registuser', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
          // First, check if the response status is not OK (not 2xx).
          if (!response.ok) {
              // If not OK, try to parse the JSON.
              return response.json().then(data => {
                  throw new Error(data.message); // Use the message from the server as the error message.
              });
          }
          return response.json(); // If everything is OK, continue to process the data.
      })
      .then(data => {
          // Handle your successful data here, if needed.
          alert('注册成功');
          // redirect to login page
          const qrCodeBase64 = data.qrcode;
          // 创建一个新的Image元素
          const image = new Image();
          image.src = qrCodeBase64;
      
          // 将图片添加到页面中某个元素内
          document.getElementById('qrCodeContainer').appendChild(image);
      })
      .catch(error => {
          // Display the error message as an alert.
          alert(error.message);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}


function login() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;
  const recaptchaResponse = grecaptcha.getResponse();
  const otp = document.getElementById('otp').value;

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(user + '.' + password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword, recaptchaResponse, otp }; // Include the user and hashed password
      fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
        // First, check if the response status is not OK (not 2xx).
        if (!response.ok) {
            // If not OK, try to parse the JSON.
            return response.json().then(data => {
                throw new Error(data.message); // Use the message from the server as the error message.
            });
        }
        return response.json(); // If everything is OK, continue to process the data.
      })
      .then(data => {
          // Handle your successful data here, if needed.
          // access_token
          alert('登录成功');
          const token = data.access_token;
          localStorage.setItem('access_token', token);

          window.location.href = '/user'; 
      })
      .catch(error => {
          // Display the error message as an alert.
          alert(error.message);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}

function resetpasswd() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;
  const captcha = document.getElementById('captcha').value;

  let passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*?[#?!@$%^&*-]).{8,}$/;
  if (!passwordRegex.test(password)) {
    alert('密码包括大小写字母，数字和特殊字符，8位以上');
    return;
  }

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(user + '.' + password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword, captcha }; // Include the user and hashed password
      fetch('/resetpasswd', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
        // First, check if the response status is not OK (not 2xx).
        if (!response.ok) {
            // If not OK, try to parse the JSON.
            return response.json().then(data => {
                throw new Error(data.message); // Use the message from the server as the error message.
            });
        }
        return response.json(); // If everything is OK, continue to process the data.
      })
      .then(data => {
          // Handle your successful data here, if needed.
          alert('重置密码成功');
          // redirect to login page
          window.location.href = '/';
      })
      .catch(error => {
          // Display the error message as an alert.
          alert(error.message);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}

function sendVerification() {
  const email = document.getElementById('user').value;
  const responseMessage = document.getElementById('responseMessage');
  const recaptchaResponse = grecaptcha.getResponse();

  const data = { email, recaptchaResponse }; // Include the user and hashed password  
  fetch('/send_verification', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json',
      },
      body: JSON.stringify(data)
  })
  .then(response => {
    // First, check if the response status is not OK (not 2xx).
    if (!response.ok) {
        // If not OK, try to parse the JSON.
        return response.json().then(data => {
            throw new Error(data.message); // Use the message from the server as the error message.
        });
    }
    return response.json(); // If everything is OK, continue to process the data.
  })
  .then(data => {
      // Handle your successful data here, if needed.
      alert('验证码已发送');
  })
  .catch(error => {
      // Display the error message as an alert.
      alert(error.message);
  });
}

// 用户页面加载时执行的函数
function loadUserProfile() {
  const token = localStorage.getItem('access_token');
  if (token) {
    fetch('/profile', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.logged_in_as) {
        document.getElementById('username').textContent = data.logged_in_as;
      } else {
        alert('页面过期，请重新登录');
        window.location.href = '/'; // 如果没有token，重定向到登录页面
      }
    })
    .catch(error => console.error('Error:', error));
  } else {
    alert('请先登录');
    window.location.href = '/'; // 如果没有token，重定向到登录页面
  }
}

function logout() {
  token = localStorage.getItem('access_token');
  fetch('/logout', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })
  .then(response => {
    if (response.status === 200) {
      // 后端返回成功响应
      localStorage.removeItem('access_token');
      window.location.href = '/';
    } else {
      // 处理其他响应，例如失败情况
      console.log('Logout failed');
    }
  })
  .catch(error => {
    console.error('Error during logout:', error);
  });
}
