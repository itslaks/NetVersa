document.getElementById('lookup-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    const domain = document.getElementById('domain').value.trim();

    const response = await fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain }),
    });
    const result = await response.json();

    const ipLocationResult = document.getElementById('ip-location-result');
    if (response.ok) {
        ipLocationResult.innerHTML = `
            <p><strong>Domain:</strong> ${domain}</p>
            <p><strong>IP Address:</strong> ${result.ip_info.ip}</p>
            <p><strong>Location:</strong> ${result.ip_info.city}, ${result.ip_info.region}, ${result.ip_info.country}</p>
        `;
    } else {
        ipLocationResult.innerHTML = `<p>${result.message}</p>`;
    }
});

document.getElementById('scan-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    const scanTypes = Array.from(document.getElementById('scan-types').selectedOptions).map(option => option.value);
    const ipAddress = document.querySelector('#ip-location-result p strong:nth-child(2)').textContent;

    const response = await fetch('/nmap_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip_address: ipAddress, scan_types: scanTypes }),
    });
    const result = await response.json();

    const nmapResult = document.getElementById('nmap-result');
    if (response.ok) {
        nmapResult.innerHTML = `<pre>${result.result}</pre>`;
    } else {
        nmapResult.innerHTML = `<p>${result.error}</p>`;
    }
});
