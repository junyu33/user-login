function register() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword }; // Include the user and hashed password
      fetch('/registuser', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
        if (response.ok) {
          alert('注册成功');
          window.location.href = "/";
        } else {
          alert('注册失败');
        }
      })
      .catch(error => {
        console.error('Error:', error);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}


function login() {
  const user = document.getElementById('user').value;
  const password = document.getElementById('password').value;

  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);

  const crypto = window.crypto || window.msCrypto;
  crypto.subtle.digest('SHA-256', passwordData)
    .then(hash => {
      const hashedPassword = Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      const data = { user, hashedPassword }; // Include the user and hashed password
      fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      })
      .then(response => {
        if (response.ok) {
          alert('登录成功');
          window.location.href = "https://example.com";
        } else {
          alert('用户名或密码错误');
        }
      })
      .catch(error => {
        console.error('Error:', error);
      });
    })
    .catch(error => {
      console.error('Error:', error);
    });
}
