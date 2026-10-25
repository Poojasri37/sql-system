const chatMessages = document.getElementById('chat-messages');
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const chatContext = document.getElementById('chat-context');

let latestPrediction = null;
let predictionReadError = null;
try {
  const savedPrediction = sessionStorage.getItem('sqlSentinel.latestPrediction');
  latestPrediction = savedPrediction ? JSON.parse(savedPrediction) : null;
  if (latestPrediction !== null && typeof latestPrediction !== 'object') {
    throw new Error('Saved prediction data has an unexpected format.');
  }
} catch (error) {
  latestPrediction = null;
  predictionReadError = error instanceof Error ? error.message : 'Unknown browser storage error.';
}

const ruleRecommendations = [
  {
    signal: 'after-hours access',
    title: 'Verify the access time',
    advice: 'Check the event against the user’s normal schedule, approved maintenance windows, and change records.'
  },
  {
    signal: 'sensitive-table access',
    title: 'Confirm sensitive-data authorization',
    advice: 'Verify the user’s role, business purpose, and whether the privilege used was necessary.'
  },
  {
    signal: 'unusually large data volume',
    title: 'Review the row volume',
    advice: 'Compare the returned row count with the user’s usual activity and the query’s stated purpose.'
  },
  {
    signal: 'large bytes transferred',
    title: 'Check the transfer destination',
    advice: 'Confirm where the data went and whether the amount transferred was approved for this task.'
  },
  {
    signal: 'abnormal query frequency',
    title: 'Investigate the query pattern',
    advice: 'Check for an unexpected loop, automation change, or account activity that could explain the spike.'
  },
  {
    signal: 'multiple query errors',
    title: 'Review failed statements',
    advice: 'Inspect the related error records and surrounding activity to distinguish a deployment issue from suspicious probing.'
  },
  {
    signal: 'very large query body',
    title: 'Review the query complexity',
    advice: 'Check whether the query size matches the approved application or reporting task.'
  },
  {
    signal: 'very high row count',
    title: 'Validate the data scope',
    advice: 'Confirm the result scope is justified and that broad access was expected for this account.'
  },
  {
    signal: 'extended query duration',
    title: 'Check the query execution',
    advice: 'Compare runtime with the usual workload and look for blocking, retries, or unusual scans.'
  }
];

const addMessage = (text, role, title) => {
  const message = document.createElement('article');
  message.className = `chat-message ${role}-message`;

  if (role === 'assistant') {
    const avatar = document.createElement('span');
    avatar.className = 'chat-avatar chat-avatar-small';
    avatar.setAttribute('aria-hidden', 'true');
    avatar.textContent = 'S';
    message.append(avatar);
  }

  const bubble = document.createElement('div');
  bubble.className = 'chat-bubble';
  if (title) {
    const heading = document.createElement('strong');
    heading.textContent = title;
    bubble.append(heading);
  }
  const paragraph = document.createElement('p');
  paragraph.textContent = text;
  bubble.append(paragraph);
  message.append(bubble);
  chatMessages.append(message);
  message.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
};

const getSignals = () => {
  if (!latestPrediction || typeof latestPrediction.explanation !== 'string') {
    return [];
  }
  if (latestPrediction.explanation.startsWith('No strong anomaly signature')) {
    return [];
  }
  return latestPrediction.explanation.split(';').map((signal) => signal.trim()).filter(Boolean);
};

const explainLatestPrediction = () => {
  if (!latestPrediction) {
    return 'There is no saved analysis in this tab yet. Go to Event analysis, enter an event or load a workspace dataset record, and run Analyze event.';
  }
  const label = latestPrediction.anomaly_label === 'anomaly'
    ? 'The model classified this event as an anomaly.'
    : 'The model classified this event as normal.';
  return `${label} Its risk score is ${latestPrediction.risk_score}/100 (${latestPrediction.risk_level}). This score is a relative model score calibrated with synthetic training data, not a probability or a confirmation of malicious activity.`;
};

const recommendForLatestPrediction = () => {
  if (!latestPrediction) {
    return 'Start with the event’s access time, account privileges, data volume, and query errors. Compare the event with approved database activity and your organization’s access policy.';
  }

  const signals = getSignals();
  const advice = ruleRecommendations
    .filter((rule) => signals.includes(rule.signal))
    .map((rule) => `${rule.title}: ${rule.advice}`);

  if (latestPrediction.risk_score >= 90) {
    advice.unshift('Prioritize review: preserve the relevant database and application logs, and verify the activity with the responsible owner.');
  } else if (latestPrediction.risk_score >= 70) {
    advice.unshift('Review the event promptly and compare it with the account’s expected activity before taking action.');
  } else if (signals.length === 0) {
    advice.push('No strong rule-based signal was reported. Confirm the event context if it is unexpected; a normal prediction does not guarantee that activity is safe.');
  }

  return advice.join('\n\n');
};

const answerQuestion = (question) => {
  const text = question.toLowerCase();
  if (text.includes('score') || text.includes('risk') || text.includes('why') || text.includes('flag')) {
    if (latestPrediction && (text.includes('why') || text.includes('flag'))) {
      const signals = getSignals();
      const reason = signals.length ? `Reported signals: ${signals.join(', ')}.` : 'The model reported no strong rule-based signals.';
      return `${explainLatestPrediction()} ${reason}`;
    }
    return explainLatestPrediction();
  }
  if (text.includes('first') || text.includes('recommend') || text.includes('investigat') || text.includes('check')) {
    return recommendForLatestPrediction();
  }
  if (text.includes('after') || text.includes('hour') || text.includes('time')) {
    const flagged = getSignals().includes('after-hours access');
    return flagged
      ? 'This event was marked as after-hours based on its timestamp. Check the account’s normal schedule, approved maintenance windows, and change records before escalating.'
      : 'The latest prediction did not report after-hours access. If the timestamp seems unusual, compare it with the user’s schedule and approved maintenance windows.';
  }
  if (text.includes('sensitive') || text.includes('privilege') || text.includes('access')) {
    const flagged = getSignals().includes('sensitive-table access');
    return flagged
      ? 'The event includes sensitive-table access. Confirm the user’s role, business purpose, and whether the privilege used was necessary.'
      : 'No sensitive-table signal was reported for the latest event. Continue to verify the account and privilege against your access policy.';
  }
  if (text.includes('volume') || text.includes('transfer') || text.includes('row') || text.includes('byte')) {
    const signals = getSignals().filter((signal) => signal.includes('volume') || signal.includes('bytes') || signal.includes('row'));
    return signals.length
      ? ruleRecommendations.filter((rule) => signals.includes(rule.signal)).map((rule) => `${rule.title}: ${rule.advice}`).join('\n\n')
      : 'The latest prediction did not report a large-volume signal. Compare row counts and transferred bytes with the user’s usual activity and the query’s business purpose.';
  }
  if (text.includes('error') || text.includes('fail') || text.includes('frequency') || text.includes('spike')) {
    const signals = getSignals().filter((signal) => signal.includes('error') || signal.includes('frequency'));
    return signals.length
      ? ruleRecommendations.filter((rule) => signals.includes(rule.signal)).map((rule) => `${rule.title}: ${rule.advice}`).join('\n\n')
      : 'No repeated-error or query-frequency signal was reported. If the activity still looks unusual, inspect nearby failed statements and compare the query pattern with the account’s baseline.';
  }
  return latestPrediction
    ? `${explainLatestPrediction()}\n\n${recommendForLatestPrediction()}`
    : 'I use local rules, not an external AI service. Ask about a risk score, after-hours access, sensitive tables, data volume, or query errors—or run an event analysis first.';
};

if (latestPrediction) {
  chatContext.textContent = `${latestPrediction.risk_score}/100 · ${latestPrediction.risk_level}`;
  addMessage(
    `${explainLatestPrediction()}\n\n${recommendForLatestPrediction()}`,
    'assistant',
    'Latest analysis'
  );
} else {
  chatContext.textContent = predictionReadError ? 'Prediction unavailable' : 'No prediction yet';
  if (predictionReadError) {
    addMessage(`I could not read the previous analysis from this browser tab: ${predictionReadError}`, 'assistant', 'Previous analysis unavailable');
  }
}

chatForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  const question = chatInput.value.trim();
  if (!question) {
    return;
  }
  addMessage(question, 'user', '');
  addMessage(answerQuestion(question), 'assistant', 'Rule-based guidance');
  chatInput.value = '';
  chatInput.focus();
});

document.querySelectorAll('[data-question]').forEach((button) => {
  button.addEventListener('click', () => {
    const question = button.dataset.question;
    addMessage(question, 'user', '');
    addMessage(answerQuestion(question), 'assistant', 'Rule-based guidance');
  });
});
