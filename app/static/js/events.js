let currentPage = 1;
const pageSize = 20;
const filterForm = document.querySelector('#filters');
const eventContainer = document.querySelector('#events');
const statusMessage = document.querySelector('#events-status');
const countBadge = document.querySelector('#event-count');
const pageLabel = document.querySelector('#page');
const detailDialog = document.querySelector('#event-detail-dialog');
const detailList = document.querySelector('#event-details');

async function loadEvents() {
  const params = new URLSearchParams(new FormData(filterForm));
  params.set('page', currentPage);
  params.set('per_page', pageSize);
  statusMessage.textContent = 'Loading events…';
  try {
    const response = await fetch(`/api/security/events?${params}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load events.');
    renderEvents(data);
  } catch (error) {
    eventContainer.replaceChildren();
    statusMessage.textContent = error.message;
    countBadge.textContent = 'Unavailable';
  }
}

function renderEvents(data) {
  const table = document.createElement('table');
  table.className = 'table table-hover align-middle event-table';
  const head = document.createElement('thead');
  const headerRow = document.createElement('tr');
  ['Time', 'Attack type', 'Severity', 'Request', 'Action', 'Details'].forEach(label => {
    const th = document.createElement('th'); th.scope = 'col'; th.textContent = label; headerRow.append(th);
  });
  head.append(headerRow);
  const body = document.createElement('tbody');
  data.items.forEach(event => {
    const row = document.createElement('tr');
    [event.timestamp, event.attack_type, event.severity, `${event.method} ${event.path}`, event.action].forEach(value => {
      const cell = document.createElement('td'); cell.textContent = value ?? ''; row.append(cell);
    });
    const detailCell = document.createElement('td');
    const detailButton = document.createElement('button');
    detailButton.type = 'button'; detailButton.className = 'btn btn-sm btn-outline-info'; detailButton.textContent = 'View';
    detailButton.setAttribute('aria-label', `View details for event ${event.id}`);
    detailButton.addEventListener('click', () => showDetails(event.id));
    detailCell.append(detailButton); row.append(detailCell); body.append(row);
  });
  table.append(head, body);
  eventContainer.replaceChildren(table);
  statusMessage.textContent = data.total ? '' : 'No events match these filters.';
  countBadge.textContent = `${data.total} ${data.total === 1 ? 'event' : 'events'}`;
  const pages = Math.max(1, Math.ceil(data.total / data.per_page));
  pageLabel.textContent = `Page ${data.page} of ${pages}`;
  document.querySelector('#prev').disabled = data.page <= 1;
  document.querySelector('#next').disabled = data.page >= pages;
}

async function showDetails(eventId) {
  detailList.replaceChildren();
  const response = await fetch(`/api/security/events/${eventId}`);
  const data = await response.json();
  if (!response.ok) {
    statusMessage.textContent = data.error || 'Could not load event details.';
    return;
  }
  const labels = { id:'Event ID', timestamp:'Timestamp', attack_type:'Attack type', severity:'Severity', method:'HTTP method', path:'Request path', reason:'Detection reason', action:'Action', response_status:'Response status', source_ip:'Source IP' };
  Object.entries(labels).forEach(([key, label]) => {
    const term = document.createElement('dt'); term.textContent = label;
    const value = document.createElement('dd'); value.textContent = data[key] ?? '—';
    detailList.append(term, value);
  });
  detailDialog.showModal();
}

filterForm.addEventListener('submit', event => { event.preventDefault(); currentPage = 1; loadEvents(); });
filterForm.addEventListener('reset', () => { setTimeout(() => { currentPage = 1; loadEvents(); }, 0); });
document.querySelector('#prev').addEventListener('click', () => { if (currentPage > 1) { currentPage -= 1; loadEvents(); } });
document.querySelector('#next').addEventListener('click', () => { currentPage += 1; loadEvents(); });
document.querySelector('#close-details').addEventListener('click', () => detailDialog.close());
detailDialog.addEventListener('click', event => { if (event.target === detailDialog) detailDialog.close(); });
loadEvents();
