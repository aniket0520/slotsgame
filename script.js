document.getElementById('webScannerForm').addEventListener('submit', function(event) {
    event.preventDefault();
    var url = document.getElementById('url').value;
    fetch('/scan?url=' + encodeURIComponent(url))
        .then(response => response.json())
        .then(data => {
            document.getElementById('results').innerHTML = data;
        })
        .catch(error => console.error('Error:', error));
});
