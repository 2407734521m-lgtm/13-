// 简单留言功能（仅前端演示，刷新后消失）
function addMessage() {
  const input = document.getElementById('msgInput');
  const text = input.value.trim();
  if (!text) return;

  const list = document.querySelector('.message-list');
  const now = new Date();
  const timeStr = `今天 ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

  const msg = document.createElement('div');
  msg.className = 'message';
  msg.innerHTML = `
    <div class="msg-avatar" style="background: linear-gradient(135deg, #a1c4fd, #c2e9fb);">我</div>
    <div class="msg-content">
      <strong>我</strong>
      <p>${escapeHtml(text)}</p>
      <span class="msg-time">${timeStr}</span>
    </div>
  `;

  list.appendChild(msg);
  list.scrollTop = list.scrollHeight;
  input.value = '';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// 回车发送
document.getElementById('msgInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') addMessage();
});
