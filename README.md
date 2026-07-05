# Recauda — servidor propio

App de cobranza para cobradiarios/pagadiarios, con servidor propio para que
todo tu equipo de cobradores trabaje sobre los mismos datos, desde donde sea,
y tú puedas administrarlos de forma remota.

No tiene dependencias externas: solo necesitas tener **Node.js** instalado.
Los datos se guardan en un archivo (`data/db.json`) en tu propio servidor.

---

## 1. Probarlo en tu computador (2 minutos)

```bash
cd recauda-server
node server.js
```

Abre `http://localhost:3000` en el navegador. Vas a ver la app.

La primera vez que arranca, se crea un usuario administrador:

- **Usuario:** Administrador
- **PIN:** 1234

**Cámbialo apenas entres** (Más → Equipo, o crea un nuevo administrador y borra
este). Como el servidor va a quedar accesible por internet, no lo dejes con el
PIN de fábrica.

---

## 2. Ponerlo en un servidor real

Cualquier servidor Linux con Node.js 18 o superior sirve (una VPS de
DigitalOcean, Hetzner, un servidor en casa, etc.).

### 2.1 Subir los archivos
Copia toda la carpeta `recauda-server` a tu servidor (por `scp`, `git`, FTP,
lo que uses normalmente).

### 2.2 Instalar Node.js (si no lo tienes)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt-get install -y nodejs
```

### 2.3 Mantenerlo siempre corriendo (pm2)
Si cierras la terminal, `node server.js` se detiene. Para que quede corriendo
todo el tiempo (y se reinicie solo si el servidor reinicia), usa `pm2`:

```bash
sudo npm install -g pm2
cd recauda-server
pm2 start server.js --name recauda
pm2 save
pm2 startup     # sigue las instrucciones que te muestre
```

Comandos útiles:
```bash
pm2 logs recauda      # ver qué está pasando
pm2 restart recauda   # reiniciar
```

### 2.4 Elegir el puerto
Por defecto usa el puerto 3000. Para cambiarlo:
```bash
PORT=8080 node server.js
# o con pm2:
PORT=8080 pm2 start server.js --name recauda
```

---

## 3. HTTPS (importante, no te lo saltes)

Tu app envía PINs al servidor para iniciar sesión. Si el servidor solo usa
`http://`, esos PINs viajan sin cifrar por internet. Antes de usarlo con tu
equipo de verdad, ponle HTTPS. La forma más simple:

### Opción fácil: Caddy (genera el certificado solo)
```bash
sudo apt install -y caddy
```
Edita `/etc/caddy/Caddyfile`:
```
tudominio.com {
    reverse_proxy localhost:3000
}
```
```bash
sudo systemctl restart caddy
```
Listo — Caddy consigue el certificado HTTPS automáticamente (necesitas que tu
dominio ya apunte a la IP del servidor).

### Opción para probar ya, sin dominio propio: Cloudflare Tunnel
Si todavía no tienes un dominio, puedes exponer tu servidor local con HTTPS
en minutos usando `cloudflared` (gratis). Es ideal para probar con tu equipo
antes de pasar a un servidor definitivo. Búscalo como "Cloudflare Tunnel quick
start" — te da una URL `https://algo.trycloudflare.com` que ya funciona.

---

## 4. Generar el APK para Android

Una vez tu servidor esté andando con HTTPS en una URL pública (por ejemplo
`https://tudominio.com`):

1. Entra a **https://www.pwabuilder.com**
2. Pega la URL de tu servidor
3. Descarga el paquete para Android
4. Eso te da un `.apk` (o `.aab` para subirlo a Google Play) listo para
   instalar

Como la app se sirve desde tu propio servidor, si más adelante haces cambios
al diseño solo actualizas los archivos del servidor — no hace falta volver a
generar el APK cada vez, porque el APK simplemente abre tu URL.

---

## 5. Cómo funciona el acceso remoto

- Cada cobrador tiene su propio usuario y PIN.
- Un **administrador** ve y administra todo: todos los clientes, todos los
  cobradores, la configuración del negocio, el plan y las copias de
  seguridad.
- Un **cobrador** solo ve y cobra a los clientes que tiene asignados.
- Todo se guarda centralizado en tu servidor: si un cobrador registra un
  cobro desde su celular, el administrador lo ve de inmediato desde el suyo.
- Si un celular pierde la conexión, la app sigue abriendo y muestra la última
  información sincronizada (modo de solo lectura) hasta que vuelva a haber
  señal.

---

## 6. Migrar datos desde la versión anterior (solo local, sin servidor)

Si ya usaste la versión anterior de Recauda (la que guardaba todo solo en el
celular, sin servidor):

1. En la versión vieja: Más → Exportar todo (descarga un `.json`)
2. En esta versión nueva, inicia sesión como administrador
3. Más → Importar → selecciona ese archivo `.json`

Esto reemplaza los datos del servidor con los que traigas del archivo.

---

## 7. Copias de seguridad

Desde Más → Exportar todo (solo administrador) descargas un `.json` con todo
tu negocio. Hazlo con frecuencia. También puedes copiar directamente el
archivo `data/db.json` de tu servidor.

---

## 8. Seguridad — checklist antes de usarlo en serio

- [ ] Cambiaste el PIN del usuario Administrador por defecto (1234)
- [ ] Todos los cobradores tienen PIN (perfiles sin PIN son un riesgo una vez
      el servidor está en internet)
- [ ] El servidor usa HTTPS, no HTTP
- [ ] Guardas copias de seguridad periódicas (`Más → Exportar todo`)
- [ ] No compartes la URL de tu servidor públicamente sin necesidad

---

## 9. Estructura de archivos

```
recauda-server/
  server.js        → el servidor (API + entrega la app)
  package.json
  public/
    index.html     → la app (interfaz)
    sw.js          → permite que la app abra sin conexión
  data/
    db.json        → tus datos (se crea solo, no lo borres a mano)
    secret.txt     → clave de seguridad interna (no la compartas ni la borres)
```

---

## 10. Problemas comunes

**"No se pudo conectar con el servidor"** — revisa que `node server.js` (o
`pm2 status`) siga corriendo, y que el puerto esté abierto en el firewall de
tu servidor.

**Perdí el PIN del administrador** — en el servidor, borra `data/db.json` y
`data/secret.txt`, reinicia el servidor: vuelve a crear el usuario
Administrador con PIN 1234 (perderás los datos, así que solo hazlo si no
tienes otro admin ni backup).

**Quiero cambiarle el diseño/textos a la app** — todo el frontend está en
`public/index.html`, es un solo archivo HTML con su CSS y JavaScript.
