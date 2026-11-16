import hashlib
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# CONFIGURACIÓN DE CONEXIÓN A POSTGRESQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:0000@localhost:5432/csirt_unad_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'evidencias'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# MODELOS DE BASE DE DATOS
class Incidente(db.Model):
    __tablename__ = 'incidentes'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(150), nullable=False)
    categoria = db.Column(db.String(50), nullable=False)
    activo_afectado = db.Column(db.String(100), nullable=False)
    severidad = db.Column(db.String(20), nullable=False)
    estado = db.Column(db.String(30), default='Abierto')
    fecha_deteccion = db.Column(db.DateTime, default=datetime.now)
    fecha_inicio_atencion = db.Column(db.DateTime, nullable=True)
    fecha_cierre = db.Column(db.DateTime, nullable=True)
    sla_limite = db.Column(db.DateTime, nullable=False)
    pasos_completados = db.Column(db.String(200), default='')
    evidencia_nombre = db.Column(db.String(150), nullable=True)
    evidencia_sha256 = db.Column(db.String(64), nullable=True)

# CATÁLOGO DE PLAYBOOKS (SOPs)
PLAYBOOKS = {
    'Phishing': [
        '1. Triaje: Analizar cabeceras SPF/DKIM/DMARC y extraer URLs/adjuntos maliciosos.',
        '2. Contención: Bloquear dominio remitente en el gateway de correo institucional.',
        '3. Erradicación: Purgar correos maliciosos de los buzones @unadvirtual.edu.co afectados.',
        '4. Recuperación: Forzar restablecimiento de credenciales y emitir alerta preventiva.'
    ],
    'Malware': [
        '1. Triaje: Identificar proceso malicioso en memoria y capturar hash del binario.',
        '2. Contención: Aislar el host/servidor de la red universitaria mediante regla de firewall.',
        '3. Forense/Erradicación: Volcar memoria RAM (Volatility) y eliminar persistencia.',
        '4. Recuperación: Validar integridad del sistema y reincorporar a producción.'
    ],
    'Web': [
        '1. Triaje: Revisar logs de Apache/Nginx para identificar payload (SQLi / XSS).',
        '2. Contención: Activar regla de bloqueo WAF para la IP atacante y parámetro vulnerable.',
        '3. Erradicación: Aplicar parche de sanitización de entradas en el código fuente.',
        '4. Recuperación: Ejecutar escaneo de verificación OWASP y restablecer servicio.'
    ],
    'Suplantacion': [
        '1. Triaje: Verificar logs de autenticación y geolocalización anómala en Campus Virtual.',
        '2. Contención: Suspender temporalmente la sesión activa y revocar tokens.',
        '3. Erradicación: Auditar cambios realizados por la cuenta comprometida.',
        '4. Recuperación: Habilitar MFA y restituir acceso al titular verificado.'
    ]
}

# MOTOR AUTOMÁTICO DE SEVERIDAD Y SLA
def calcular_severidad_y_sla(categoria, activo, fecha_base=None):
    base = fecha_base if fecha_base else datetime.now()
    activo_lower = activo.lower()
    if 'moodle' in activo_lower or 'base de datos' in activo_lower or categoria == 'Malware':
        return 'Crítico (P1)', base + timedelta(minutes=15)
    elif categoria == 'Web' or 'portal' in activo_lower:
        return 'Alto (P2)', base + timedelta(minutes=30)
    elif categoria == 'Phishing':
        return 'Medio (P3)', base + timedelta(hours=2)
    else:
        return 'Bajo (P4)', base + timedelta(hours=8)

# RUTAS WEB
@app.route('/')
def index():
    incidentes = Incidente.query.order_by(Incidente.id.desc()).all()
    cerrados = [i for i in incidentes if i.estado == 'Cerrado' and i.fecha_cierre and i.fecha_inicio_atencion]
    
    mttd = round(sum([(i.fecha_inicio_atencion - i.fecha_deteccion).total_seconds() / 60 for i in cerrados]) / len(cerrados), 2) if cerrados else 0
    mttr = round(sum([(i.fecha_cierre - i.fecha_inicio_atencion).total_seconds() / 60 for i in cerrados]) / len(cerrados), 2) if cerrados else 0

    return render_template('index.html', incidentes=incidentes, mttd=mttd, mttr=mttr)

@app.route('/registrar', methods=['POST'])
def registrar():
    titulo = request.form['titulo']
    categoria = request.form['categoria']
    activo = request.form['activo']
    severidad, sla_limite = calcular_severidad_y_sla(categoria, activo)
    
    nuevo = Incidente(titulo=titulo, categoria=categoria, activo_afectado=activo, severidad=severidad, sla_limite=sla_limite)
    db.session.add(nuevo)
    db.session.commit()
    return redirect(url_for('index'))

# NUEVA RUTA: EDITAR INCIDENTE
@app.route('/editar/<int:id>', methods=['POST'])
def editar_incidente(id):
    inc = Incidente.query.get_or_404(id)
    nueva_categoria = request.form['categoria']
    nuevo_activo = request.form['activo']
    
    # Si cambia la categoría, reiniciamos los pasos del playbook anterior
    if inc.categoria != nueva_categoria:
        inc.pasos_completados = ''

    inc.titulo = request.form['titulo']
    inc.categoria = nueva_categoria
    inc.activo_afectado = nuevo_activo
    inc.estado = request.form['estado']

    # Recalcula severidad y SLA según los datos editados
    severidad, sla_limite = calcular_severidad_y_sla(nueva_categoria, nuevo_activo, inc.fecha_deteccion)
    inc.severidad = severidad
    inc.sla_limite = sla_limite

    if inc.estado == 'Abierto':
        inc.fecha_cierre = None
    elif inc.estado == 'Cerrado' and not inc.fecha_cierre:
        inc.fecha_cierre = datetime.now()

    db.session.commit()
    return redirect(url_for('index'))

@app.route('/api/webhook/alerta', methods=['POST'])
def webhook_alerta():
    data = request.json
    severidad, sla_limite = calcular_severidad_y_sla(data['categoria'], data['activo'])
    nuevo = Incidente(
        titulo=data['titulo'],
        categoria=data['categoria'],
        activo_afectado=data['activo'],
        severidad=severidad,
        sla_limite=sla_limite
    )
    db.session.add(nuevo)
    db.session.commit()
    return jsonify({'status': 'Incidente ingestado', 'id': nuevo.id, 'severidad': severidad}), 201

@app.route('/incidente/<int:id>', methods=['GET', 'POST'])
def gestionar_incidente(id):
    inc = Incidente.query.get_or_404(id)
    if not inc.fecha_inicio_atencion:
        inc.fecha_inicio_atencion = datetime.now()
        inc.estado = 'En Contencion'
        db.session.commit()

    if request.method == 'POST':
        pasos = request.form.getlist('pasos')
        inc.pasos_completados = ','.join(pasos)

        archivo = request.files.get('evidencia')
        if archivo and archivo.filename != '':
            contenido = archivo.read()
            sha256_hash = hashlib.sha256(contenido).hexdigest()
            ruta = os.path.join(app.config['UPLOAD_FOLDER'], archivo.filename)
            with open(ruta, 'wb') as f:
                f.write(contenido)
            inc.evidencia_nombre = archivo.filename
            inc.evidencia_sha256 = sha256_hash

        if 'cerrar_caso' in request.form:
            inc.estado = 'Cerrado'
            inc.fecha_cierre = datetime.now()

        db.session.commit()
        return redirect(url_for('gestionar_incidente', id=inc.id))

    playbook = PLAYBOOKS.get(inc.categoria, [])
    completados = inc.pasos_completados.split(',') if inc.pasos_completados else []
    return render_template('incident.html', inc=inc, playbook=playbook, completados=completados)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)