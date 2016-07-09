function restoreAndSkipContent() {
  var hidden = document.querySelector('.skip-me');

  hidden.classList.add('unhide');
  window.scroll(0, hidden.offsetHeight);
};
restoreAndSkipContent();