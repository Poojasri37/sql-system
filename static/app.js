const form = document.getElementById('predict-form');
const output = document.getElementById('prediction-output');

const getToken = async () => {
  const body = { username: 'admin', password: 'admin123' };
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await response.json();
  return data.access_token;
};

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const fd = new FormData(form);
  const payload = {
    timestamp: fd.get('timestamp'),
    user_id: fd.get('user_id'),
    database_name: fd.get('database_name'),
    query_type: fd.get('query_type'),
    table_name: fd.get('table_name'),
    privilege_level: fd.get('privilege_level'),
    query_length: Number(fd.get('query_length')),
    rows_returned: Number(fd.get('rows_returned')),
    duration_ms: Number(fd.get('duration_ms')),
    bytes_transferred: Number(fd.get('bytes_transferred')),
    num_join_tables: Number(fd.get('num_join_tables')),
    error_count: Number(fd.get('error_count')),
    is_successful: Number(fd.get('is_successful')),
    query_frequency: Number(fd.get('query_frequency')),
    after_hours: Number(fd.get('after_hours')),
    sensitive_table: Number(fd.get('sensitive_table'))
  };

  const token = await getToken();
  const response = await fetch('/api/predict', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(payload)
  });

  const result = await response.json();
  output.textContent = JSON.stringify(result, null, 2);
});
