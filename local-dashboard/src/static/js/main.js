

document.addEventListener('DOMContentLoaded', function() {
    const charts = {};
    
    
    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleString();
    };
    
    
    const toggleLoading = (elementId, isLoading) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.style.display = isLoading ? 'block' : 'none';
        }
    };
    
    
    const showNotification = (message, type = 'info') => {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
        notification.setAttribute('role', 'alert');
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        document.body.appendChild(notification);
        
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 5000);
    };
    
    
    const getStatusIndicator = (isMalicious, isAnonymous) => {
        if (isMalicious) {
            return '<span class="badge bg-danger">Malicioso</span>';
        } else if (isAnonymous) {
            return '<span class="badge bg-warning text-dark">VPN/Tor</span>';
        } else {
            return '<span class="badge bg-success">Normal</span>';
        }
    };
    
    
    const generateIpInfoHtml = (ipInfo) => {
        if (!ipInfo) return 'Información no disponible';
        
        const country = ipInfo.country || 'Desconocido';
        const city = ipInfo.city || 'Desconocido';
        const org = ipInfo.org || 'Desconocido';
        
        return `
            <div>
                <strong>País:</strong> ${country}<br>
                <strong>Ciudad:</strong> ${city}<br>
                <strong>Organización:</strong> ${org}
            </div>
        `;
    };
    
    
    const initDataTable = (tableId, options = {}) => {
        const defaultOptions = {
            language: {
                url: '//cdn.datatables.net/plug-ins/1.10.25/i18n/Spanish.json'
            },
            order: [[0, 'desc']],
            pageLength: 10,
            lengthMenu: [5, 10, 25, 50]
        };
        
        const tableOptions = { ...defaultOptions, ...options };
        const table = $(`#${tableId}`).DataTable(tableOptions);
        
        return table;
    };
    
    
    const initChart = (canvasId, config) => {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, config);
        
        return chart;
    };
    
   
    const updateChart = (chartId, data) => {
        const chart = Chart.getChart(chartId);
        if (chart) {
            chart.data = data;
            chart.update();
        }
    };
    
    
    const getCountryFlag = (countryCode) => {
        if (!countryCode) return '';
        
       
        const codePoints = countryCode
            .toUpperCase()
            .split('')
            .map(char => 127397 + char.charCodeAt());
        
        return String.fromCodePoint(...codePoints);
    };
    
    
    window.updateStats = function() {
        fetch('/api/stats')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Error al cargar estadísticas');
                }
                return response.json();
            })
            .then(data => {
                
                updateCounter('login-attempts-count', data.login_attempts);
                updateCounter('unique-usernames-count', data.unique_usernames);
                updateCounter('unique-passwords-count', data.unique_passwords);
                updateCounter('total-ips-count', data.unique_ips);
                updateCounter('anonymous-connections-count', data.anonymous_connections);
                updateCounter('detected-attacks-count', data.detected_attacks);
                updateCounter('malicious-ips-count', data.malicious_ips);
                updateCounter('detected-bots-count', data.detected_bots);
                
                
                if (data.last_updated) {
                    const lastUpdatedElement = document.getElementById('last-updated-time');
                    if (lastUpdatedElement) {
                        lastUpdatedElement.textContent = formatDate(data.last_updated);
                    }
                }
                
                
                updateHourlyChart(data.hourly_chart);
                updateDailyChart(data.daily_chart);
            })
            .catch(error => {
                console.error('Error al cargar estadísticas:', error);
                showNotification('Error al cargar estadísticas. Intente de nuevo más tarde.', 'danger');
            });
    };
    
    
    const updateCounter = (elementId, value) => {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const currentValue = parseInt(element.textContent.replace(/,/g, ''), 10) || 0;
        if (currentValue !== value) {
            animateCounter(element, currentValue, value);
        }
    };
    
    
    const animateCounter = (element, start, end) => {
        const duration = 1000; 
        const startTime = performance.now();
        
        const updateCount = (currentTime) => {
            const elapsedTime = currentTime - startTime;
            
            if (elapsedTime < duration) {
                const progress = elapsedTime / duration;
                const currentCount = Math.floor(start + (end - start) * progress);
                element.textContent = currentCount.toLocaleString();
                requestAnimationFrame(updateCount);
            } else {
                element.textContent = end.toLocaleString();
            }
        };
        
        requestAnimationFrame(updateCount);
    };
    
    
    const updateHourlyChart = (chartData) => {
        const hourlyChart = document.getElementById('hourly-chart');
        const hourlyChartLoading = document.getElementById('hourly-chart-loading');
        const hourlyChartEmpty = document.getElementById('hourly-chart-empty');
        
        if (hourlyChart && hourlyChartLoading && hourlyChartEmpty) {
            if (chartData) {
                hourlyChart.src = 'data:image/png;base64,' + chartData;
                hourlyChart.classList.remove('d-none');
                hourlyChartLoading.classList.add('d-none');
                hourlyChartEmpty.classList.add('d-none');
            } else {
                hourlyChart.classList.add('d-none');
                hourlyChartLoading.classList.add('d-none');
                hourlyChartEmpty.classList.remove('d-none');
            }
        }
    };
    
    
    const updateDailyChart = (chartData) => {
        const dailyChart = document.getElementById('daily-chart');
        const dailyChartLoading = document.getElementById('daily-chart-loading');
        const dailyChartEmpty = document.getElementById('daily-chart-empty');
        
        if (dailyChart && dailyChartLoading && dailyChartEmpty) {
            if (chartData) {
                dailyChart.src = 'data:image/png;base64,' + chartData;
                dailyChart.classList.remove('d-none');
                dailyChartLoading.classList.add('d-none');
                dailyChartEmpty.classList.add('d-none');
            } else {
                dailyChart.classList.add('d-none');
                dailyChartLoading.classList.add('d-none');
                dailyChartEmpty.classList.remove('d-none');
            }
        }
    };
    
   
    const setupPeriodicUpdates = () => {
       
        setInterval(() => {
            window.updateStats();
            
            const path = window.location.pathname;
            
            if (path.includes('/logins')) {
                window.initLoginsPage();
            } else if (path.includes('/attacks')) {
                window.initAttacksPage();
            } else if (path.includes('/credentials')) {
                window.initCredentialsPage();
            } else if (path.includes('/geography')) {
                window.initGeographyPage();
            } else if (path.includes('/bots')) {
                window.initBotsPage();
            } else if (path.includes('/contacts')) {
                window.initContactsPage();
            }
        }, 60000);
    };
    
    
    window.updateStats();
    setupPeriodicUpdates();
    
   
    const path = window.location.pathname;
    
    if (path.includes('/logins')) {
        window.initLoginsPage();
    } else if (path.includes('/attacks')) {
        window.initAttacksPage();
    } else if (path.includes('/credentials')) {
        window.initCredentialsPage();
    } else if (path.includes('/geography')) {
        window.initGeographyPage();
    } else if (path.includes('/bots')) {
        window.initBotsPage();
    } else if (path.includes('/contacts')) {
        window.initContactsPage();
    }

    
    window.initCredentialsPage = () => {
        const tableLoading = document.getElementById('credentials-table-loading');
        const tableEmpty = document.getElementById('credentials-table-empty');
        const tableContainer = document.getElementById('credentials-table-container');
        
        if (tableLoading && tableEmpty && tableContainer) {
            toggleLoading(true, tableLoading, tableEmpty, tableContainer);
            
            fetch('/api/credentials')
                .then(response => response.json())
                .then(data => {
                    
                    if (data && data.credentials && data.credentials.length > 0) {
                        const hasTable = $('#credentials-table').length > 0;
                        
                        if (!hasTable) {
                           
                            const table = $('<table id="credentials-table" class="table table-striped table-bordered w-100"></table>');
                            $('#credentials-table-container').append(table);
                            
                            
                            $('#credentials-table').DataTable({
                                data: data.credentials,
                                columns: [
                                    { data: 'username', title: 'Usuario' },
                                    { data: 'password', title: 'Contraseña' },
                                    { 
                                        data: 'count', 
                                        title: 'Intentos',
                                        render: function(data) {
                                            return `<span class="badge bg-primary">${data}</span>`;
                                        }
                                    },
                                    { 
                                        data: 'last_seen', 
                                        title: 'Último Intento',
                                        render: function(data) {
                                            return formatDate(data);
                                        }
                                    }
                                ],
                                order: [[2, 'desc']],
                                ...initDataTable()
                            });
                        } else {
                            
                            const table = $('#credentials-table').DataTable();
                            table.clear().rows.add(data.credentials).draw();
                        }
                        
                        toggleLoading(false, tableLoading, tableEmpty, tableContainer);
                    } else {
                        toggleLoading(false, tableLoading, tableEmpty, tableContainer, true);
                    }
                })
                .catch(error => {
                    console.error('Error fetching credentials data:', error);
                    toggleLoading(false, tableLoading, tableEmpty, tableContainer, true);
                    showNotification('Error al cargar los datos de credenciales', 'danger');
                });
        }
    };

   
    window.initGeographyPage = () => {
        const mapLoading = document.getElementById('map-loading');
        const mapEmpty = document.getElementById('map-empty');
        const mapContainer = document.getElementById('map-container');
        
        if (mapLoading && mapEmpty && mapContainer) {
            toggleLoading(true, mapLoading, mapEmpty, mapContainer);
            
            fetch('/api/geography')
                .then(response => response.json())
                .then(data => {
                    if (data && data.countries && Object.keys(data.countries).length > 0) {
                        
                        if (!window.worldMap) {
                            window.worldMap = new jsVectorMap({
                                selector: '#world-map',
                                map: 'world',
                                backgroundColor: 'transparent',
                                zoomOnScroll: true,
                                regionStyle: {
                                    initial: {
                                        fill: '#e9ecef',
                                        "fill-opacity": 0.8,
                                        stroke: '#dee2e6',
                                        "stroke-width": 1,
                                        "stroke-opacity": 1
                                    },
                                    hover: {
                                        "fill-opacity": 0.9
                                    },
                                    selected: {
                                        fill: '#6c757d'
                                    }
                                },
                                series: {
                                    regions: [{
                                        values: {},
                                        scale: ['#b3deff', '#0d6efd'],
                                        normalizeFunction: 'polynomial'
                                    }]
                                },
                                onRegionTipShow: function(event, tooltip, code) {
                                    if (data.countries[code]) {
                                        const country = data.countries[code];
                                        tooltip.html(
                                            `<div class="map-tooltip">
                                                <h6 class="mb-0">${country.name}</h6>
                                                <p class="mb-0">Intentos: <strong>${country.count}</strong></p>
                                                <p class="mb-0">IPs únicas: <strong>${country.unique_ips}</strong></p>
                                            </div>`
                                        );
                                    } else {
                                        tooltip.html(
                                            `<div class="map-tooltip">
                                                <h6 class="mb-0">${tooltip.html()}</h6>
                                                <p class="mb-0">Sin actividad registrada</p>
                                            </div>`
                                        );
                                    }
                                }
                            });
                        }
                        
                        
                        const mapValues = {};
                        const countryRows = [];
                        
                        for (const [code, country] of Object.entries(data.countries)) {
                            mapValues[code] = country.count;
                            countryRows.push({
                                code: code,
                                name: country.name,
                                count: country.count,
                                unique_ips: country.unique_ips
                            });
                        }
                        
                        
                        window.worldMap.series.regions[0].params.values = mapValues;
                        window.worldMap.update();
                        
                        
                        const hasTable = $('#countries-table').length > 0;
                        
                        if (!hasTable) {
                            
                            const table = $('<table id="countries-table" class="table table-striped table-bordered w-100"></table>');
                            $('#countries-table-container').append(table);
                            
                           
                            $('#countries-table').DataTable({
                                data: countryRows,
                                columns: [
                                    { 
                                        data: 'code', 
                                        title: 'País',
                                        render: function(data, type, row) {
                                            return `<span>${getCountryFlag(data)} ${row.name}</span>`;
                                        }
                                    },
                                    { 
                                        data: 'count', 
                                        title: 'Intentos',
                                        render: function(data) {
                                            return `<span class="badge bg-primary">${data}</span>`;
                                        }
                                    },
                                    { 
                                        data: 'unique_ips', 
                                        title: 'IPs Únicas',
                                        render: function(data) {
                                            return `<span class="badge bg-info">${data}</span>`;
                                        }
                                    }
                                ],
                                order: [[1, 'desc']],
                                ...initDataTable()
                            });
                        } else {
                            
                            const table = $('#countries-table').DataTable();
                            table.clear().rows.add(countryRows).draw();
                        }
                        
                        toggleLoading(false, mapLoading, mapEmpty, mapContainer);
                    } else {
                        toggleLoading(false, mapLoading, mapEmpty, mapContainer, true);
                    }
                })
                .catch(error => {
                    console.error('Error fetching geography data:', error);
                    toggleLoading(false, mapLoading, mapEmpty, mapContainer, true);
                    showNotification('Error al cargar los datos geográficos', 'danger');
                });
        }
    };

    
    window.initBotsPage = () => {
        const tableLoading = document.getElementById('bots-table-loading');
        const tableEmpty = document.getElementById('bots-table-empty');
        const tableContainer = document.getElementById('bots-table-container');
        
        if (tableLoading && tableEmpty && tableContainer) {
            toggleLoading(true, tableLoading, tableEmpty, tableContainer);
            
            fetch('/api/bots')
                .then(response => response.json())
                .then(data => {
                    
                    if (data && data.bots && data.bots.length > 0) {
                        const hasTable = $('#bots-table').length > 0;
                        
                        if (!hasTable) {
                            
                            const table = $('<table id="bots-table" class="table table-striped table-bordered w-100"></table>');
                            $('#bots-table-container').append(table);
                            
                            
                            $('#bots-table').DataTable({
                                data: data.bots,
                                columns: [
                                    { 
                                        data: 'ip', 
                                        title: 'IP',
                                        render: function(data, type, row) {
                                            return generateIpInfoHtml(row);
                                        }
                                    },
                                    { 
                                        data: 'user_agent', 
                                        title: 'User Agent',
                                        render: function(data) {
                                            if (data && data.length > 50) {
                                                return `<span title="${data}">${data.substring(0, 50)}...</span>`;
                                            }
                                            return data || 'N/A';
                                        }
                                    },
                                    { 
                                        data: 'bot_type', 
                                        title: 'Tipo',
                                        render: function(data) {
                                            let badgeClass = 'bg-secondary';
                                            if (data === 'crawler') badgeClass = 'bg-info';
                                            if (data === 'scanner') badgeClass = 'bg-warning';
                                            if (data === 'attacker') badgeClass = 'bg-danger';
                                            return `<span class="badge ${badgeClass}">${data}</span>`;
                                        }
                                    },
                                    { 
                                        data: 'page', 
                                        title: 'Página',
                                        render: function(data) {
                                            return data || 'N/A';
                                        }
                                    },
                                    { 
                                        data: 'timestamp', 
                                        title: 'Fecha',
                                        render: function(data) {
                                            return formatDate(data);
                                        }
                                    }
                                ],
                                order: [[4, 'desc']],
                                ...initDataTable()
                            });
                        } else {
                            
                            const table = $('#bots-table').DataTable();
                            table.clear().rows.add(data.bots).draw();
                        }
                        
                        toggleLoading(false, tableLoading, tableEmpty, tableContainer);
                    } else {
                        toggleLoading(false, tableLoading, tableEmpty, tableContainer, true);
                    }
                })
                .catch(error => {
                    console.error('Error fetching bots data:', error);
                    toggleLoading(false, tableLoading, tableEmpty, tableContainer, true);
                    showNotification('Error al cargar los datos de bots', 'danger');
                });
        }
    };

    
    window.initContactsPage = () => {
        const tableLoading = document.getElementById('contacts-table-loading');
        const tableEmpty = document.getElementById('contacts-table-empty');
        const tableContainer = document.getElementById('contacts-table-container');
        
        if (tableLoading && tableEmpty && tableContainer) {
            toggleLoading(true, tableLoading, tableEmpty, tableContainer);
            
            fetch('/api/contacts')
                .then(response => response.json())
                .then(data => {
                    
                    if (data && data.contacts && data.contacts.length > 0) {
                        const hasTable = $('#contacts-table').length > 0;
                        
                        if (!hasTable) {
                           
                            const table = $('<table id="contacts-table" class="table table-striped table-bordered w-100"></table>');
                            $('#contacts-table-container').append(table);
                            
                            
                            $('#contacts-table').DataTable({
                                data: data.contacts,
                                columns: [
                                    { 
                                        data: 'ip', 
                                        title: 'IP',
                                        render: function(data, type, row) {
                                            return generateIpInfoHtml(row);
                                        }
                                    },
                                    { 
                                        data: 'email', 
                                        title: 'Email'
                                    },
                                    { 
                                        data: 'name', 
                                        title: 'Nombre'
                                    },
                                    { 
                                        data: 'subject',
                                        title: 'Asunto' 
                                    },
                                    { 
                                        data: 'message', 
                                        title: 'Mensaje',
                                        render: function(data) {
                                            if (data && data.length > 50) {
                                                return `<span title="${data}">${data.substring(0, 50)}...</span>`;
                                            }
                                            return data || 'N/A';
                                        }
                                    },
                                    { 
                                        data: 'malicious', 
                                        title: 'Estado',
                                        render: function(data, type, row) {
                                            return getStatusIndicator(row.malicious, row.is_anonymous);
                                        }
                                    },
                                    { 
                                        data: 'timestamp', 
                                        title: 'Fecha',
                                        render: function(data) {
                                            return formatDate(data);
                                        }
                                    }
                                ],
                                order: [[6, 'desc']],
                                ...initDataTable()
                            });
                        } else {
                            
                            const table = $('#contacts-table').DataTable();
                            table.clear().rows.add(data.contacts).draw();
                        }
                        
                        toggleLoading(false, tableLoading, tableEmpty, tableContainer);
                    } else {
                        toggleLoading(false, tableLoading, tableEmpty, tableContainer, true);
                    }
                })
                .catch(error => {
                    console.error('Error fetching contacts data:', error);
                    toggleLoading(false, tableLoading, tableEmpty, tableContainer, true);
                    showNotification('Error al cargar los datos de contactos', 'danger');
                });
        }
    };
}); 