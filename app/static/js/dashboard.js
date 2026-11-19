let attackChart, trendChart, severityChart;
const labels = {
  total_requests: 'Total requests', safe_requests: 'Safe requests', blocked_requests: 'Blocked requests',
  sqli_attempts: 'SQL injection attempts', xss_attempts: 'XSS attempts', invalid_input_attempts: 'Invalid input attempts'
};
const tones = {
  total_requests:'blue', safe_requests:'green', blocked_requests:'red',
  sqli_attempts:'red', xss_attempts:'cyan', invalid_input_attempts:'amber'
};
const gridColor = 'rgba(148, 163, 184, 0.14)';

function chartOptions() {
  Chart.defaults.color = '#a9bbd0';
  Chart.defaults.borderColor = gridColor;
  return {responsive:true, maintainAspectRatio:false, plugins:{legend:{labels:{color:'#c4d2e2',usePointStyle:true,boxWidth:10}}}, scales:{x:{grid:{color:gridColor},ticks:{color:'#91a6bd'}},y:{grid:{color:gridColor},ticks:{color:'#91a6bd'},beginAtZero:true}}};
}

async function loadDashboard() {
  const status = document.querySelector('#dashboard-status');
  if (status) status.textContent = '';
  try {
    const response = await fetch(`/api/analytics/attacks?days=${document.querySelector('#days').value}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load dashboard data.');
    const cards = Object.entries(data.kpis).map(([key,value]) => {
      const column = document.createElement('div'); column.className = 'col-6 col-lg-4 col-xxl-2';
      const card = document.createElement('div'); card.className = `card kpi-card kpi-${tones[key] || 'blue'}`;
      const label = document.createElement('span'); label.className='kpi-label'; label.textContent=labels[key] || key;
      const number = document.createElement('strong'); number.className='kpi-number'; number.textContent=String(value);
      card.append(label,number); column.append(card); return column;
    });
    document.querySelector('#kpis').replaceChildren(...cards);

    const attackData = {labels:data.attacks.map(item=>item.attack_type),datasets:[{data:data.attacks.map(item=>item.count),backgroundColor:['#3b82f6','#06b6d4','#ef4444','#f59e0b','#8b5cf6','#22c55e'],borderColor:'#101a2b',borderWidth:3}]};
    const trendData = {labels:data.trend.map(item=>item.day),datasets:[{label:'Safe',data:data.trend.map(item=>item.safe),borderColor:'#22c55e',backgroundColor:'#22c55e',tension:.25},{label:'Blocked',data:data.trend.map(item=>item.blocked),borderColor:'#f05252',backgroundColor:'#f05252',tension:.25}]};
    const severityColors={LOW:'#22c55e',MEDIUM:'#f59e0b',HIGH:'#ef4444',CRITICAL:'#b91c1c'};
    const severityData={labels:data.severity.map(item=>item.severity),datasets:[{label:'Events',data:data.severity.map(item=>item.count),backgroundColor:data.severity.map(item=>severityColors[item.severity]||'#06b6d4'),borderRadius:6}]};
    [attackChart,trendChart,severityChart].forEach(chart=>chart?.destroy());
    attackChart=new Chart(document.querySelector('#attacks'),{type:'doughnut',data:attackData,options:{...chartOptions(),cutout:'66%',scales:{}}});
    trendChart=new Chart(document.querySelector('#trend'),{type:'line',data:trendData,options:chartOptions()});
    severityChart=new Chart(document.querySelector('#severity'),{type:'bar',data:severityData,options:chartOptions()});

    const recentRows=data.recent.map(event=>{
      const row=document.createElement('tr');
      [event.timestamp,event.attack_type,event.severity,`${event.method} ${event.path}`,event.action].forEach(value=>{const cell=document.createElement('td');cell.textContent=value;row.append(cell);});
      return row;
    });
    document.querySelector('#recent').replaceChildren(...recentRows);
  } catch (error) {
    if (status) status.textContent=error.message;
  }
}

document.querySelector('#days').addEventListener('change',loadDashboard);
loadDashboard();
setInterval(loadDashboard,15000);
