# Your SmartGuard configuration for Docker / Tu configuración de SmartGuard para Docker

**English.** This folder is mounted read-only at `/etc/smartguard` in the `smartguard` container.
It is optional: with nothing here, the defaults shipped in the image (`config/`) are used.

- Copy `config/rules.yaml`, `config/sites.yaml` or `config/bots.yaml` here to replace that file.
- Put extra rules in `rules.d/*.yaml` (same format as the `rules:` list of `rules.yaml`).
- Apply the changes with `docker compose restart smartguard`.

Rules can also be created from the dashboard (**Rules** tab); those are stored in the
`smartguard_data` volume, not here.

**Español.** Esta carpeta se monta en solo lectura en `/etc/smartguard` del contenedor `smartguard`.
Es opcional: si está vacía se usan los valores por defecto de la imagen (`config/`).

- Copia aquí `config/rules.yaml`, `config/sites.yaml` o `config/bots.yaml` para sustituir ese archivo.
- Pon reglas adicionales en `rules.d/*.yaml` (mismo formato que la lista `rules:` de `rules.yaml`).
- Aplica los cambios con `docker compose restart smartguard`.

Las reglas también se pueden crear desde el panel (pestaña **Reglas**); esas se guardan en el
volumen `smartguard_data`, no aquí.
