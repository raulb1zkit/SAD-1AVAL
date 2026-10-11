# Sitio público del vault

Esta carpeta contiene únicamente la capa de publicación. El contenido fuente sigue estando en la raíz:

- `../apuntes/`
- `../docs/`

El workflow `.github/workflows/deploy-pages.yml` descarga Quartz durante el despliegue, copia esas dos carpetas al contenido del sitio y publica el resultado en GitHub Pages.

Para previsualizarlo localmente, consulta la documentación de Quartz. No se debe copiar ni mantener una segunda versión de los apuntes o PDFs dentro de `site/`.
