function copyCmd(id, btn) {
  const text = document.getElementById(id)?.textContent?.trim() || '';
  navigator.clipboard.writeText(text).then(() => {
    const prev = btn.textContent;
    btn.textContent = '✓ Copied';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = prev;
      btn.classList.remove('copied');
    }, 1400);
  }).catch(() => {
    btn.textContent = '✗';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1000);
  });
}
