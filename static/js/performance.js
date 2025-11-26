// ====================================================
// OPTIMIZACIONES DE RENDIMIENTO Y VELOCIDAD
// ====================================================

// 1. LAZY LOADING DE IMÁGENES
document.addEventListener('DOMContentLoaded', function() {
  // Lazy loading para navegadores que no lo soportan nativamente
  if ('loading' in HTMLImageElement.prototype) {
    // Navegador soporta lazy loading nativo
    const images = document.querySelectorAll('img[data-src]');
    images.forEach(img => {
      img.src = img.dataset.src;
      img.loading = 'lazy';
    });
  } else {
    // Implementar lazy loading con Intersection Observer
    const imageObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src;
          img.classList.remove('lazy');
          imageObserver.unobserve(img);
        }
      });
    });

    const images = document.querySelectorAll('img.lazy, img[data-src]');
    images.forEach(img => imageObserver.observe(img));
  }
});

// 2. DEFER DE SCRIPTS NO CRÍTICOS
function deferStyles() {
  const links = document.querySelectorAll('link[rel="stylesheet"][data-defer]');
  links.forEach(link => {
    link.rel = 'stylesheet';
  });
}

// 3. PRECONNECT A RECURSOS EXTERNOS
function preconnectResources() {
  const domains = [
    'https://cdn.jsdelivr.net',
    'https://cdnjs.cloudflare.com',
    'https://fonts.googleapis.com',
    'https://fonts.gstatic.com'
  ];
  
  domains.forEach(domain => {
    const link = document.createElement('link');
    link.rel = 'preconnect';
    link.href = domain;
    link.crossOrigin = 'anonymous';
    document.head.appendChild(link);
  });
}

// 4. OPTIMIZACIÓN DE FORMULARIOS
function optimizeForms() {
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    // DESHABILITADO: Validación en tiempo real para evitar checkmarks verdes
    // La validación se maneja en el servidor
    
    // Solo eliminar clases is-invalid cuando el usuario empiece a escribir
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
      let timeout;
      input.addEventListener('input', function() {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
          // Solo remover errores, no agregar validación visual
          input.classList.remove('is-invalid');
        }, 300);
      });
    });
  });
}

// 5. OPTIMIZACIÓN DE SCROLL
(function() {
  let ticking = false;
  window.addEventListener('scroll', function() {
    if (!ticking) {
      window.requestAnimationFrame(function() {
        // Lógica de scroll (animaciones, etc)
        handleScroll();
        ticking = false;
      });
      ticking = true;
    }
  });
})();

function handleScroll() {
  // Implementar animaciones o efectos de scroll aquí
  const scrollPosition = window.scrollY;
  
  // Ejemplo: Fade in de elementos al hacer scroll
  const fadeElements = document.querySelectorAll('.fade-in-on-scroll');
  fadeElements.forEach(element => {
    const elementTop = element.getBoundingClientRect().top;
    const windowHeight = window.innerHeight;
    
    if (elementTop < windowHeight - 100) {
      element.classList.add('visible');
    }
  });
}

// 6. PREFETCH DE PÁGINAS IMPORTANTES Y AL HOVER
function prefetchPages() {
  // Prefetch de páginas importantes inmediato
  const importantPages = [
    '/services',
    '/appointment',
    '/about'
  ];
  
  importantPages.forEach(page => {
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = page;
    document.head.appendChild(link);
  });
  
  // Prefetch al hacer hover sobre enlaces internos (carga instantánea)
  const internalLinks = document.querySelectorAll('a[href^="/"]');
  internalLinks.forEach(link => {
    link.addEventListener('mouseenter', function() {
      const href = this.getAttribute('href');
      if (href && !document.querySelector(`link[rel="prefetch"][href="${href}"]`)) {
        const prefetch = document.createElement('link');
        prefetch.rel = 'prefetch';
        prefetch.href = href;
        document.head.appendChild(prefetch);
      }
    }, { once: true, passive: true });
  });
}

// 7. OPTIMIZACIÓN DE IMÁGENES
function optimizeImages() {
  // Convertir imágenes a WebP si el navegador lo soporta
  const supportsWebP = (() => {
    const canvas = document.createElement('canvas');
    if (canvas.getContext && canvas.getContext('2d')) {
      return canvas.toDataURL('image/webp').indexOf('data:image/webp') === 0;
    }
    return false;
  })();
  
  if (supportsWebP) {
    const images = document.querySelectorAll('img[data-webp]');
    images.forEach(img => {
      if (img.dataset.webp) {
        img.src = img.dataset.webp;
      }
    });
  }
}

// 8. ANALYTICS LIGERO (solo si es necesario)
function initLightAnalytics() {
  // Implementar tracking ligero de eventos importantes
  const importantButtons = document.querySelectorAll('[data-track]');
  importantButtons.forEach(button => {
    button.addEventListener('click', function() {
      const action = this.dataset.track;
      // Enviar evento a analytics (implementar según necesidad)
      console.log('Evento:', action);
    });
  });
}

// 9. COMPRESIÓN DE DATOS LOCALES
function compressLocalData() {
  // Si usas localStorage, comprimir datos grandes
  const Storage = {
    set: function(key, value) {
      const compressed = LZString.compressToUTF16(JSON.stringify(value));
      localStorage.setItem(key, compressed);
    },
    get: function(key) {
      const compressed = localStorage.getItem(key);
      if (!compressed) return null;
      return JSON.parse(LZString.decompressFromUTF16(compressed));
    }
  };
  
  window.OptimizedStorage = Storage;
}

// 10. GESTIÓN INTELIGENTE DE MEMORIA
function cleanupUnusedElements() {
  // Limpiar elementos ocultos o no visibles
  const hiddenElements = document.querySelectorAll('[style*="display: none"]');
  hiddenElements.forEach(element => {
    if (element.dataset.keepAlive !== 'true') {
      element.innerHTML = '';
    }
  });
}

// 11. DETECCIÓN DE CONEXIÓN LENTA
function detectSlowConnection() {
  const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  
  if (connection) {
    if (connection.effectiveType === 'slow-2g' || connection.effectiveType === '2g') {
      // Reducir calidad de imágenes, deshabilitar animaciones
      document.body.classList.add('slow-connection');
      console.log('Conexión lenta detectada, optimizando...');
    }
  }
}

// 12. REGISTRO DE SERVICE WORKER
function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/static/sw.js')
        .then(registration => {
          console.log('Service Worker registrado:', registration.scope);
        })
        .catch(error => {
          console.log('Error al registrar Service Worker:', error);
        });
    });
  }
}

// INICIALIZACIÓN
document.addEventListener('DOMContentLoaded', function() {
  // Ejecutar optimizaciones
  preconnectResources();
  optimizeImages();
  optimizeForms();
  detectSlowConnection();
  prefetchPages();
  initLightAnalytics();
  
  // Registrar Service Worker para PWA
  registerServiceWorker();
  
  // Limpiar memoria periódicamente (cada 5 minutos)
  setInterval(cleanupUnusedElements, 300000);
});

// EXPORTAR PARA USO GLOBAL
window.Performance = {
  optimizeImages,
  prefetchPages,
  registerServiceWorker
};


