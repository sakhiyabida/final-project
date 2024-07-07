document.addEventListener('DOMContentLoaded', function() {
    const scanTypeSelect = document.getElementById('scan_type');
    const nmapForm = document.getElementById('nmap_form');
    const shodanForm = document.getElementById('shodan_form');
    const shodanOptionSelect = document.getElementById('shodan_option');
    const shodanOrg = document.getElementById('shodan_org');
    const shodanRange = document.getElementById('shodan_range');

    scanTypeSelect.addEventListener('change', function() {
        if (scanTypeSelect.value === 'nmap') {
            nmapForm.classList.remove('hidden');
            shodanForm.classList.add('hidden');
        } else if (scanTypeSelect.value === 'shodan') {
            nmapForm.classList.add('hidden');
            shodanForm.classList.remove('hidden');
        }
    });

    shodanOptionSelect.addEventListener('change', function() {
        if (shodanOptionSelect.value === 'org') {
            shodanOrg.classList.remove('hidden');
            shodanRange.classList.add('hidden');
        } else if (shodanOptionSelect.value === 'ip_range') {
            shodanOrg.classList.add('hidden');
            shodanRange.classList.remove('hidden');
        }
    });
});
