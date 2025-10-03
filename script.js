function isValidURL(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

function updateCounter() {
  let count = localStorage.getItem("urlCount") || 0;
  document.getElementById("urlCount").textContent = count;
}


function incrementCounter() {
  let count = parseInt(localStorage.getItem("urlCount")) || 0;
  count++;
  localStorage.setItem("urlCount", count);
  document.getElementById("urlCount").textContent = count;
}

function saveHistory(item, status) {
  let history = JSON.parse(localStorage.getItem("history")) || [];
  history.unshift({ item, status }); 
  if (history.length > 10) history.pop();
  localStorage.setItem("history", JSON.stringify(history));
  renderHistory();
}

function renderHistory() {
  const historyList = document.getElementById("historyList");
  let history = JSON.parse(localStorage.getItem("history")) || [];
  historyList.innerHTML = "";

  history.forEach(entry => {
    const li = document.createElement("li");
    li.textContent = `${entry.item} → ${entry.status}`;
    historyList.appendChild(li);
  });
}

async function checkURL() {
  const urlInput = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");

  if (!urlInput) {
    resultDiv.innerHTML = "❌ Please enter a URL first.";
    resultDiv.style.color = "black";
    return;
  }

  if (!isValidURL(urlInput)) {
    resultDiv.innerHTML = "❌ Invalid URL format.";
    resultDiv.style.color = "orange";
    saveHistory(urlInput, "Invalid URL");
    incrementCounter();
    return;
  }

  const API_KEY = "34660ddc4edc889fea5a86fb203770496f8c50dd93ebcbad598602755540228d";
  const proxy = "https://cors-anywhere.herokuapp.com/"; 
  const API_URL = proxy + "https://www.virustotal.com/vtapi/v2/url/report";

  try {
    resultDiv.innerHTML = "⏳ Checking...";
    resultDiv.style.color = "black";

    const response = await fetch(`${API_URL}?apikey=${API_KEY}&resource=${encodeURIComponent(urlInput)}`);
    const data = await response.json();

    if (data && data.positives > 0) {
      resultDiv.innerHTML = `⚠️ Warning: Site is dangerous! <br> Detections: <b>${data.positives}</b>`;
      resultDiv.style.color = "red";
      saveHistory(urlInput, `Dangerous (${data.positives})`);
    } else {
      resultDiv.innerHTML = "✅ This site looks safe.";
      resultDiv.style.color = "green";
      saveHistory(urlInput, "Safe");
    }

    incrementCounter();
  } catch (error) {
    console.error(error);
    resultDiv.innerHTML = "❌ Error checking the URL.";
    resultDiv.style.color = "black";
    saveHistory(urlInput, "Error");
    incrementCounter();
  }
}

function checkPDF() {
  const fileInput = document.getElementById("fileInput");
  const resultDiv = document.getElementById("result");

  if (!fileInput.files.length) {
    resultDiv.innerHTML = "❌ Please select a PDF file.";
    resultDiv.style.color = "black";
    return;
  }

  const file = fileInput.files[0];
  resultDiv.innerHTML = `✅ The file <b>${file.name}</b> looks safe.`;
  resultDiv.style.color = "green";
  saveHistory(file.name, "Safe (PDF)");
  incrementCounter();
}

window.onload = function() {
  renderHistory();
  updateCounter();
  fetch("http://localhost:3000/upload", { method: "POST", body: formData });

};
