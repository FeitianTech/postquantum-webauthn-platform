// Tests give the page's data the way the server does: a
// <script type="application/json" id="..."> block, read by shared/utils/page-data.js
// when a module loads. The blocks go in <head>, so a test that replaces the body
// keeps them.

export function setPageData(id, value) {
  let block = document.getElementById(id);
  if (!block) {
    block = document.createElement('script');
    block.type = 'application/json';
    block.id = id;
    document.head.appendChild(block);
  }
  block.textContent = JSON.stringify(value);
}

export function removePageData(id) {
  document.getElementById(id)?.remove();
}
