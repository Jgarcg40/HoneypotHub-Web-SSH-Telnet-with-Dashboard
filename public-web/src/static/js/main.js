
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if(targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if(targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });

    
    const animateCounters = () => {
        const counters = document.querySelectorAll('.card-text.display-4');
        
        counters.forEach(counter => {
            const target = parseInt(counter.innerText);
            let count = 0;
            const increment = target / 30; 
            
            const updateCounter = () => {
                if (count < target) {
                    count += increment;
                    counter.innerText = Math.ceil(count);
                    setTimeout(updateCounter, 30);
                } else {
                    counter.innerText = target;
                }
            };
            
            updateCounter();
        });
    };

    
    if (document.querySelector('.card-text.display-4')) {
        animateCounters();
    }

    
    const autoCloseAlerts = () => {
        setTimeout(() => {
            document.querySelectorAll('.alert.auto-close').forEach(alert => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            });
        }, 5000);
    };

    
    if (document.querySelector('.alert.auto-close')) {
        autoCloseAlerts();
    }

    
    const simulateRealTimeActivity = () => {
        const activityList = document.querySelector('.list-group');
        if (!activityList) return;

        const activities = [
            { title: 'Escaneo de seguridad', description: 'Escaneo rutinario completado sin incidencias' },
            { title: 'Respaldo de datos', description: 'Respaldo automático programado iniciado' },
            { title: 'Actualización de sistema', description: 'Nueva actualización disponible para instalar' }
        ];

        let index = 0;

        setInterval(() => {
            const now = new Date();
            const timeString = `${now.getHours()}:${now.getMinutes().toString().padStart(2, '0')}`;
            
            const newItem = document.createElement('li');
            newItem.className = 'list-group-item d-flex justify-content-between align-items-start';
            newItem.innerHTML = `
                <div class="ms-2 me-auto">
                    <div class="fw-bold">${activities[index].title}</div>
                    ${activities[index].description}
                </div>
                <span class="text-muted small">Ahora, ${timeString}</span>
            `;
            
            newItem.style.opacity = '0';
            
            
            if (activityList.children.length >= 5) {
                activityList.removeChild(activityList.lastElementChild);
            }
            
            activityList.prepend(newItem);
            
            
            setTimeout(() => {
                newItem.style.transition = 'opacity 0.5s';
                newItem.style.opacity = '1';
            }, 10);
            
            index = (index + 1) % activities.length;
        }, 60000); 
    };

    
    if (document.querySelector('.list-group')) {
        simulateRealTimeActivity();
    }
}); 