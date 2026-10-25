const form = document.getElementById('predict-form');
const output = document.getElementById('prediction-output');
const predictButton = document.getElementById('predict-button');
const loadDatasetButton = document.getElementById('load-dataset-event');
const eventSource = document.getElementById('event-source');

let datasetEventId = null;

const renderError = (message) => {
  output.className = 'prediction-result json-result has-error';
  output.textContent = JSON.stringify({ error: message }, null, 2);
};

form?.addEventListener('input', () => {
  if (datasetEventId !== null) {
    datasetEventId = null;
    eventSource.textContent = 'Manually edited event details.';
  }
});

form?.addEventListener('change', () => {
  if (datasetEventId !== null) {
    datasetEventId = null;
    eventSource.textContent = 'Manually edited event details.';
  }
});

loadDatasetButton?.addEventListener('click', async () => {
  loadDatasetButton.disabled = true;
  loadDatasetButton.textContent = 'Loading…';

  try {
    const response = await fetch('/api/dataset/random', {
      headers: { Accept: 'application/json' }
    });
    const record = await response.json();
    if (!response.ok) {
      throw new Error(record.error || 'Could not load a record from the workspace dataset.');
    }

    for (const [name, value] of Object.entries(record)) {
      const field = form.elements.namedItem(name);
      if (field && name !== 'event_id' && name !== 'source') {
        field.value = String(value);
      }
    }
    datasetEventId = record.event_id;
    eventSource.textContent = `Loaded dataset event #${record.event_id} from ${record.source} (synthetic).`;
    output.className = 'prediction-result json-result';
    output.textContent = 'Dataset record loaded. Analyze event to see its prediction JSON.';
  } catch (error) {
    eventSource.textContent = 'Dataset record could not be loaded.';
    renderError(error instanceof Error ? error.message : 'An unexpected error occurred.');
  } finally {
    loadDatasetButton.disabled = false;
    loadDatasetButton.textContent = 'Load dataset record';
  }
});

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(form);
  const payload = Object.fromEntries(formData.entries());
  const numericFields = [
    'query_length',
    'rows_returned',
    'duration_ms',
    'bytes_transferred',
    'num_join_tables',
    'error_count',
    'is_successful',
    'query_frequency',
    'sensitive_table'
  ];

  for (const field of numericFields) {
    payload[field] = Number(payload[field]);
  }

  predictButton.disabled = true;
  predictButton.textContent = 'Analyzing…';
  output.className = 'prediction-result json-result';
  output.textContent = 'Analyzing event…';

  try {
    const tokenResponse = await fetch('/api/session-token', {
      headers: { Accept: 'application/json' }
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) {
      throw new Error(tokenData.error || 'Your session has expired. Please sign in again.');
    }

    const response = await fetch('/api/predict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenData.access_token}`
      },
      body: JSON.stringify(payload)
    });
    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || 'The prediction request failed.');
    }

    const prediction = {
      ...result,
      input_source: datasetEventId === null
        ? 'Manually entered event'
        : `Synthetic workspace dataset event #${datasetEventId}`
    };
    output.className = 'prediction-result json-result has-result';
    output.textContent = JSON.stringify(prediction, null, 2);
    eventSource.textContent = prediction.input_source;
    try {
      sessionStorage.setItem('sqlSentinel.latestPrediction', JSON.stringify(prediction));
    } catch (storageError) {
      if (storageError instanceof DOMException && ['QuotaExceededError', 'SecurityError'].includes(storageError.name)) {
        eventSource.textContent += ' Recommendations may not be able to read this result in this browser tab.';
      } else {
        throw storageError;
      }
    }
  } catch (error) {
    renderError(error instanceof Error ? error.message : 'An unexpected error occurred.');
  } finally {
    predictButton.disabled = false;
    predictButton.innerHTML = '<span aria-hidden="true">⌁</span> Analyze event';
  }
});
