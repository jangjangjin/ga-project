document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("registerForm");

  if (form) {
    form.addEventListener("submit", async function (event) {
      event.preventDefault();

      const data = {
        name: document.getElementById("registerName").value,
        email: document.getElementById("registerEmail").value,
        phone: document.getElementById("registerPhone").value,
        login_id: document.getElementById("registerId").value,
        password: document.getElementById("registerPassword").value
      };

      try {
        const response = await fetch("http://172.18.1.100:5000/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data)
        });

        const result = await response.json();
        if (response.ok) {
          alert("회원가입 성공!");
          form.reset();
          // 예: 로그인 페이지 이동 window.location.href = 'login.html';
        } else {
          alert("오류: " + result.error);
        }
      } catch (error) {
        alert("서버 연결 실패: " + error.message);
      }
    });
  }
});
