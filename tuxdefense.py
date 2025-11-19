#/usr/bin/env python3
"""
AUR Security AI Layer - Servidor de Inteligencia Artificial
copyright (C) 2025 [TuxDefense by Ricandres]
License: GPL-3.0-or-later


Este servidor implementa un modelo de AI opensource que implementa patrones de malware y proporciona prediciones en tiempo real a traves de una API REST,
"""


import os 
import sys
import json
import time
import hashlib
from datatime import datetime
from typing import Dict, List, Optional, Tuple


import numpy as np
import tensorflow as tf
from tensorflow import keras
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import sqlite3
import threading
import logging
# ============================================================
# CONFIGURACIÓN DEL SERVIDOR
# ============================================================
class SeverConfig:
        """Configuración del servidor de IA"""
    # Información del servidor
    VERSION = "1.0.0"
    SERVER_NAME = "TuxDefense AI Server"


    # Puerto y host
    HOST = "0.0.0.0" # Accesible desde cualquier IP
    PORT = 8080

    # Base de datos
    DATABASE_PATH = "tuxdefense_ai.db"
    MODEL_PATH = "tuxdefense_model.h5"
    EMBEDDING_DIM = 128
    MAX_SEQUENCE_LENGTH = 512
    VOCAB_SIZE = 10000

    # Entrenamiento
    BATCH_SIZE = 32
    RETRAIN_INTEVAL_HOURS = 24 = 36000 # 1 hora en segundos
    MIN_SAMPLES_FOR_TRAINING = 100
    #API
    API_KEY_REQUIRED = True
    RATE_LIMIT_PER_MINUTE = 100


    #Logs
        LOG_LEVEL = logging.INFO
        LOG_FILE = "tuxdefense_ai.log"

# ============================================================
# CONFIGURAR LOGGING
# ============================================================
logging.basicConfig(
    level=ServerConfig.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(ServerConfig.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
# ============================================================
# BASE DE DATOS DE APRENDIZAJE
# ============================================================
class LearningDatabase:
    """
    Base de datos que almacena todos los escaneos de todos los usuarios
    para entrenar el modelo de IA
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
        self._initialize_database()
    def _init_database(self):
        """Inicializar base de datos SQLite"""
        os.makedirs(os.path_dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
                # Tabla de escaneos (datos de entrenamiento)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pkgbuild_hash TEXT NOT NULL,
                pkgbuild_content TEXT NOT NULL,
                package_name TEXT NOT NULL,
                threat_level INTEGER NOT NULL,
                is_malicious BOOLEAN NOT NULL,
                confidence REAL NOT NULL,
                user_feedback TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_id TEXT,
                INDEX idx_hash (pkgbuild_hash),
                INDEX idx_timestamp (timestamp)
            )
        ''')
            # Tabla de patrones aprendidos
        cursor.execute(''' CREATE TABLE IF NOT EXISTS learned_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                pattern_value TEXT NOT NULL,
                threat_score REAL NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(pattern_type, pattern_value)
            )
        ''')
                # Tabla de métricas del modelo
        cursor.execute('''

                CREATE TABLE IF NOT EXISTS model_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                accuracy REAL NOT NULL,
                precision REAL NOT NULL,
                recall REAL NOT NULL,
                f1_score REAL NOT NULL,
                samples_count INTEGER NOT NULL,
                training_time REAL NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
                # Tabla de usuarios/clientes (para estadísticas)
        cursor.execute('''

                CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT UNIQUE NOT NULL,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_scans INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0
            )
        ''')
        self.conn.commit()
        logger.info("Base de datos inicializada: {self.db_path}")
    def add_scan(self, data: Dict) -> int:
                """Agregar un escaneo a la base de datos"""
            cursor = self.conn.cursor()
    

            cursor.execute('''
INSERT INTO scans (
                pkgbuild_hash, pkgbuild_content, package_name,
                threat_level, is_malicious, confidence,
                client_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['pkgbuild_hash'],
            data['pkgbuild_content'],
            data['package_name'],
            data['threat_level'],
            data['is_malicious'],
            data['confidence'],
            data.get('client_id', 'anonymous')
        ))
        
        scan_id = cursor.lastrowid
            # Actualizar estadísticas del cliente
        if data.get('client_id;'):
        cursor.execute('''
                INSERT INTO clients (client_id, total_scans, threats_found)
                VALUES (?, 1, ?)
                ON CONFLICT(client_id) DO UPDATE SET
                    total_scans = total_scans + 1,
                    threats_found = threats_found + ?,
                    last_seen = CURRENT_TIMESTAMP
            ''', (
                data['client_id'],
                1 if data['is_malicious'] else 0,
                1 if data['is_malicious'] else 0
            ))
        self.conn.commit()
        logger.debug(f"Escaneo agregado: {data['package_name']} (ID: {scan_id})")
        return scan_id
    def add_feedback(self, scan_id: int, feedback: str):         """Agregar feedback del usuario sobre una predicción"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE scans SET user_feedback = ? WHERE id = ?
        ''', (feedback, scan_id))
        self.conn.commit()
    logger.info(f"Feedback agregado para escaneo ID: {scan_id}: {feedback}")
    def get_training_data(self, limit: int - 10000) -> Tuple[List[str], List[Dict]]:
        cursor = self.conn.cursor()
        cursor.execute('''
SELECT pkgbuild_content, threat_level, is_malicious, user_feedback
            FROM scans
            WHERE user_feedback IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit // 2,))
        verified_rows = cursor.fetchall()

        all_rows = list(verified_rows) + list(recent_rows)

        x = [row['pkgbuild_content'] for row in all_rows]
        y = [{
            'threat_level': row['threat_level'],
            'is_malicious': row['is_malicious']
            'verified': row['user_feedback'] is ['TP', 'TN'] if row ['user_feedback'] else false } for row in all_rows]
        logger.info(f"Datos de entrenamiento obtenidos: {len(x)} muestras")
        return x, y
    def get_statistics(self) -> Dict:
            """Obtener estadísticas globales"""
        cursor = self.coon.cursor()
    

    stats = {}


            # Total de escaneos
        cursor.exacute('SELECT COUNT (*) as total FROM scans')
    stats['total_scans'] = cursor.fetchone()['total']
            # Escaneos con feedback
    cursor.execute('SELECT COUNT(*) as verified FROM scans WHERE user_feedback IS NOT NULL')
        stats['verified_scans'] = cursor.fetchone()['verified']
            # Amenazas detectadas
cursor.execute('SELECT COUNT(*) as threats FROM scans WHERE is_malicious = 1')
        stats['threats_detected'] = cursor.fetchone()['threats']
# Clientes únicos
        cursor.execute('SELECT COUNT(*) as clients FROM clients')
        stats['unique_clients'] = cursor.fetchone()['clients']
Escaneos últimas 24h
        cursor.execute('''
            SELECT COUNT(*) as recent 
            FROM scans 
            WHERE timestamp > datetime('now', '-1 day')
        ''')
        stats['scans_24h'] = cursor.fetchone()['recent']
        
        # Confianza promedio
        cursor.execute('SELECT AVG(confidence) as avg_conf FROM scans')
        stats['avg_confidence'] = round(cursor.fetchone()['avg_conf'] or 0.0, 3)
        
        return stats
# ============================================================
# MODELO DE IA PARA DETECCIÓN DE MALWARE
# ============================================================
class ThreatDetectorAI:
    """
    Modelo de IA que aprende patrones de malware en PKGBUILDs
    """
    
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        self.is_trained = False
        self.version = "1.0"
        
        self._init_tokenizer()
        self._load_or_create_model()
    
    def _init_tokenizer(self):
        """Inicializar tokenizador para procesar PKGBUILDs"""
        self.tokenizer = keras.preprocessing.text.Tokenizer(
            num_words=ServerConfig.VOCAB_SIZE,
            oov_token="<UNK>",
            filters='!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n'
        )
        logger.info("Tokenizador inicializado")
        def _load_or_create_model(self):
        """Cargar modelo existente o crear uno nuevo"""
        if os.path.exists(self.model_path):
            try:
                self.model = keras.models.load_model(self.model_path)
                self.is_trained = True
                logger.info(f"Modelo cargado desde {self.model_path}")
            except Exception as e:
                logger.error(f"Error al cargar el modelo: {e}")
                self._create_model()
        else:
            self._create_model()
    def _create_model(self):
        """Crear arquitectura del modelo de IA"""
        logger.info("Creando nuevo modelo de IA...")
        
        # Input
        input_layer = keras.layers.Input(
            shape=(ServerConfig.MAX_SEQUENCE_LENGTH,),
            name='pkgbuild_input'
        )
        
        # Embedding
        embedding = keras.layers.Embedding(
            input_dim=ServerConfig.VOCAB_SIZE,
            output_dim=ServerConfig.EMBEDDING_DIM,
            mask_zero=True
        )(input_layer)
    
    #Bidirectional LSTM para captura contexto
        lstml = keras.layers.Bidirectional(
            keras.layers.LSTM(64, return_sequences=True)
        )(embedding)
    

        lstm2 = keras.layers.Bidirectional(
            keras.layers.LSTM(32)
        )(lstm1)
    # Dense layers
        dense1 = keras.layers.Dense(64, activation='relu')(lstm2)
        dropout1 = keras.layers.Dropout(0.3)(dense1)
        dense2 = keras.layers.Dense(32, activation='relu')(dropout1)
        dropout2 = keras.layers.Dropout(0.2)(dense2)
        
        # Outputs
        threat_level_output = keras.layers.Dense(
            5, activation='softmax', name='threat_level'
        )(dropout2)
        
        malicious_output = keras.layers.Dense(
            1, activation='sigmoid', name='is_malicious'
        )(dropout2)
        
        confidence_output = keras.layers.Dense(
            1, activation='sigmoid', name='confidence'
        )(dropout2)
        
        # Crear modelo
        self.model = keras.Model(
            inputs=input_layer,
            outputs={
                'threat_level': threat_level_output,
                'is_malicious': malicious_output,
                'confidence': confidence_output
            }
        )
        #compilar
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss={
                'threat_level': 'categorical_crossentropy',
                'is_malicious': 'binary_crossentropy',
                'confidence': 'mse'
            },
            loss_weights={
                'threat_level': 1.0,
                'is_malicious': 2.0,  # Priorizar detección de malware
                'confidence': 0.5
            },
            metrics={
                'threat_level': 'accuracy',
                'is_malicious': ['accuracy', 'precision', 'recall'],
                'confidence': 'mae'
            }
        )
        
        logger.info(f"Modelo creado con {self.model.count_params():,} parámetros")
    
    def preprocess(self, pkgbuild_content: str) -> np.ndarray:
        """Preprocesar PKGBUILD para el modelo"""
        # Tokenizar
        sequences = self.tokenizer.texts_to_sequences([pkgbuild_content])
        
        # Padding
        padded = keras.preprocessing.sequence.pad_sequences(
            sequences,
            maxlen=ServerConfig.MAX_SEQUENCE_LENGTH,
            padding='post',
            truncating='post'
        )
        
        return padded
    def predict(self, pkgbuild_content: str) -> Dict:
        """
        Predecir si un PKGBUILD es malicioso
        
        Returns:
            {
                'is_malicious': bool,
                'threat_level': int (0-4),
                'confidence': float (0-1),
                'reasoning': str
            }
        """
        if not self.is_trained:
            logger.warning("modelo no entrada , usando heuristicas básicas")
            return self._heuristic_fullback(pkgbuild_content)
        
        #preprocesar
        x = self.preprocess(pkgbuild_content)

        # Predecir
        predictions = self.model.predict(X, verbose=0)

        threat_level = int (np.argmax(predictions['threat_level'][0]))
        is_malicious = float (preditions['is_malicious'][0][0]) > 0.5
        confidence = float (predictions['confidence'][0][0])



        # generacion explicaicon
        reasing = self._generate_reasoning(
            pkgbuild_content, threat_level, is_malicious, confidence
        )



        return {
            'is_malicious': is_malicious,
            'threat_level': threat_level,
            'confidence': confidence,
            'reasoning': reasoning,
            'model_version': self.version
        }
    def _heuristic_fallback(self, pkgbuild_content: str) -> Dict:
        """Heurística simple cuando el modelo no está entrenado"""
        dangerous_patterns = [
            'curl.*|.*bash', 'wget.*|.*sh', 'eval', 
            'base64 -d', 'nc -l', '/etc/passwd'
        ]
        score = sum(1 for pattern in dangerous_patterns if pattern in pkgbuild.lower())



        is_malicious = score >= 2
        threat_level = min(score, 4)
        confidence = 0.6 # Baja confianza sin modelo entrenado

        return {
            'is_malicious': is_malicious,
            'threat_level': threat_level,
            'confidence': confidence,
            'reasoning': f"Análisis heurístico: {score} patrones sospechosos detectados",
            'model_version': 'heuristic'
        }
    
    def _generate_reasoning(self, pkgbuild: str, threat_level: int, 
                        is_malicious: bool, confidence: float) -> str:
        """Generar explicación de la predicción"""
        if threat_level == 0:
            return "No se detectaron patrones sospechosos en el PKGBUILD"
        
        reasons = []
                # Analizar patrones específicos
        if 'curl' in pkgbuild.lower() or 'wget' in pkgbuild.lower():
            reasons.append("descarga archivos de internet")
        if 'eval' in pkgbuild.lower():
            reasons.append("ejecuta código dinámico")
        if 'base64' in pkgbuild.lower():
            reasons.append("contiene código ofuscado")
        if 'sudo' in pkgbuild.lower():
            reasons.append("requiere privilegios elevados")
        
        if reasons:
            return f"El PKGBUILD {', '.join(reasons)} (confianza: {confidence:.0%})"
        else:
            return f"Patrones sospechosos detectados por IA (confianza: {confidence:.0%})"
    
    def train(self, X: List[str], y: List[Dict]) -> Dict:
        """
        Entrenar el modelo con nuevos datos
        
        Args:
            X: Lista de contenidos de PKGBUILD
            y: Lista de labels con threat_level, is_malicious, verified
        
        Returns:
            Métricas del entrenamiento
        """
        if len(X) < ServerConfig.MIN_SAMPLES_FOR_TRAINING:
            logger.warning(f"Insuficientes muestras: {len(X)} < {ServerConfig.MIN_SAMPLES_FOR_TRAINING}")
            return {'error': 'insufficient_samples'}
        
        logger.info(f"Iniciando entrenamiento con {len(X)} muestras...")
        start_time = time.time()
        
        # Ajustar tokenizador
        self.tokenizer.fit_on_texts(X)
                # Preprocesar datos
sequences = self.tokenizer.texts_to_sequences(X)
        X_padded = keras.preprocessing.sequence.pad_sequences(
            sequences,
            maxlen=ServerConfig.MAX_SEQUENCE_LENGTH,
            padding='post',
            truncating='post'
        )
        
        # Preparar labels
        y_threat = np.array([
            keras.utils.to_categorical(label['threat_level'], 5) 
            for label in y
        ])
        y_malicious = np.array([[1.0 if label['is_malicious'] else 0.0] for label in y])
        y_confidence = np.array([[1.0 if label['verified'] else 0.7] for label in y])
        
        # Entrenar
        history = self.model.fit(
            X_padded,
            {
                'threat_level': y_threat,
                'is_malicious': y_malicious,
                'confidence': y_confidence
            },
            batch_size=ServerConfig.BATCH_SIZE,
            epochs=10,
            validation_split=0.2,
            verbose=1
        )
        
        training_time = time.time() - start_time
        
        # Guardar modelo
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        self.model.save(self.model_path)
        self.is_trained = True
    # Métricas
        metrics = {
            'accuracy': float(history.history['is_malicious_accuracy'][-1]),
            'val_accuracy': float(history.history['val_is_malicious_accuracy'][-1]),
            'loss': float(history.history['loss'][-1]),
            'training_time': training_time,
            'samples': len(X),
            'epochs': 10
        }
        
        logger.info(f"Entrenamiento completado en {training_time:.2f}s")
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        
        return metrics

# ============================================================
# API REST DEL SERVIDOR
# ============================================================

app = Flask(__name__)
CORS(app)  # Permitir requests desde cualquier origen

# Inicializar componentes
db = LearningDatabase(ServerConfig.DB_PATH)
ai_model = ThreatDetectorAI(ServerConfig.MODEL_PATH)

# Lock para operaciones concurrentes
training_lock = threading.Lock()
is_training = False

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Verificar estado del servidor"""
    return jsonify({
        'status': 'healthy',
        'server': ServerConfig.SERVER_NAME,
        'version': ServerConfig.VERSION,
        'model_trained': ai_model.is_trained,
        'training_in_progress': is_training,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/v1/predict', methods=['POST'])
def predict():
    """
    Predecir si un PKGBUILD es malicioso
    
    POST /api/v1/predict
    {
        "package_name": "ejemplo-aur",
        "pkgbuild": "pkgname=ejemplo\n...",
        "client_id": "usuario123" (opcional)
    }
    """
    data = request.json
    
    if not data or 'pkgbuild' not in data:
        return jsonify({'error': 'Missing pkgbuild content'}), 400
    
    package_name = data.get('package_name', 'unknown')
    pkgbuild = data['pkgbuild']
    client_id = data.get('client_id', 'anonymous')
    
    # Calcular hash
    pkgbuild_hash = hashlib.sha256(pkgbuild.encode()).hexdigest()
    
    # Predecir
    prediction = ai_model.predict(pkgbuild)
    
    # Guardar en base de datos para aprendizaje futuro
    scan_data = {
        'pkgbuild_hash': pkgbuild_hash,
        'pkgbuild_content': pkgbuild,
        'package_name': package_name,
        'threat_level': prediction['threat_level'],
        'is_malicious': prediction['is_malicious'],
        'confidence': prediction['confidence'],
        'client_id': client_id
    }
    
    scan_id = db.add_scan(scan_data)
    
    # Preparar respuesta
    response = {
        'scan_id': scan_id,
        'package_name': package_name,
        'pkgbuild_hash': pkgbuild_hash,
        **prediction,
        'timestamp': datetime.now().isoformat()
    }
    
    logger.info(f"Predicción: {package_name} -> malicioso={prediction['is_malicious']}, "
            f"confianza={prediction['confidence']:.2f}")
    
    return jsonify(response)

@app.route('/api/v1/feedback', methods=['POST'])
def submit_feedback():
    """
    Enviar feedback sobre una predicción
    
    POST /api/v1/feedback
    {
        "scan_id": 123,
        "feedback": "TP"  # TP (True Positive), FP (False Positive), TN, FN
    }
    """
    data = request.json
    
    scan_id = data.get('scan_id')
    feedback = data.get('feedback')
    
    if not scan_id or feedback not in ['TP', 'FP', 'TN', 'FN']:
        return jsonify({'error': 'Invalid feedback'}), 400
    
    db.add_feedback(scan_id, feedback)
    
    logger.info(f"Feedback recibido: scan_id={scan_id}, feedback={feedback}")
    
    return jsonify({
        'status': 'feedback_received',
        'scan_id': scan_id,
        'feedback': feedback
    })

@app.route('/api/v1/train', methods=['POST'])
def trigger_training():
    """Disparar re-entrenamiento del modelo"""
    global is_training
    
    if is_training:
        return jsonify({
            'status': 'training_in_progress',
            'message': 'El modelo ya se está entrenando'
        }), 409
    
    def train_async():
        global is_training
        with training_lock:
            is_training = True
            try:
                logger.info("Iniciando entrenamiento asíncrono...")
                
                X, y = db.get_training_data(limit=10000)
                
                if len(X) < ServerConfig.MIN_SAMPLES_FOR_TRAINING:
                    logger.warning(f"Insuficientes muestras: {len(X)}")
                    return
                
                metrics = ai_model.train(X, y)
                
                # Guardar métricas en BD
                cursor = db.conn.cursor()
                cursor.execute('''
                    INSERT INTO model_metrics (
                        version, accuracy, precision, recall, f1_score,
                        samples_count, training_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ai_model.version,
                    metrics.get('accuracy', 0.0),
                    0.0,  # TODO: calcular precision
                    0.0,  # TODO: calcular recall
                    0.0,  # TODO: calcular F1
                    metrics['samples'],
                    metrics['training_time']
                ))
                db.conn.commit()
                
                logger.info("Entrenamiento completado exitosamente")
                
            except Exception as e:
                logger.error(f"Error durante entrenamiento: {e}")
            finally:
                is_training = False
    
    # Iniciar entrenamiento en thread separado
    threading.Thread(target=train_async, daemon=True).start()
    
    return jsonify({
        'status': 'training_started',
        'message': 'Entrenamiento iniciado en segundo plano'
    })

@app.route('/api/v1/stats', methods=['GET'])
def get_statistics():
    """Obtener estadísticas del servidor"""
    stats = db.get_statistics()
    
    stats['server'] = ServerConfig.SERVER_NAME
    stats['version'] = ServerConfig.VERSION
    stats['model_trained'] = ai_model.is_trained
    stats['model_version'] = ai_model.version
    
    return jsonify(stats)

# ============================================================
# ENTRENAMIENTO AUTOMÁTICO PERIÓDICO
# ============================================================

def auto_retrain_loop():
    """Loop que re-entrena el modelo periódicamente"""
    global is_training
    
    while True:
        time.sleep(ServerConfig.RETRAIN_INTERVAL)
        
        if is_training:
            logger.info("Entrenamiento ya en progreso, esperando...")
            continue
        
        stats = db.get_statistics()
        
        if stats['total_scans'] >= ServerConfig.MIN_SAMPLES_FOR_TRAINING:
            logger.info("Iniciando re-entrenamiento automático...")
            
            with training_lock:
                is_training = True
                try:
                    X, y = db.get_training_data()
                    metrics = ai_model.train(X, y)
                    logger.info(f"Re-entrenamiento automático completado: "
                            f"accuracy={metrics['accuracy']:.4f}")
                except Exception as e:
                    logger.error(f"Error en re-entrenamiento: {e}")
                finally:
                    is_training = False

# ============================================================
# PUNTO DE ENTRADA
# ============================================================

if __name__ == '__main__':
    print("=" * 70)
    print(f"  {ServerConfig.SERVER_NAME} v{ServerConfig.VERSION}")
    print("  Copyright (C) 2025 Ricandres")
    print("  License: GPL-3.0-or-later")
    print("=" * 70)
    print(f"  Host: {ServerConfig.HOST}:{ServerConfig.PORT}")
    print(f"  Database: {ServerConfig.DB_PATH}")
    print(f"  Model: {ServerConfig.MODEL_PATH}")
    print(f"  Model trained: {ai_model.is_trained}")
    print("=" * 70)
    print()
    
    # Iniciar thread de re-entrenamiento automático
    retrain_thread = threading.Thread(target=auto_retrain_loop, daemon=True)
    retrain_thread.start()
    logger.info("Thread de re-entrenamiento automático iniciado")
    
    # Iniciar servidor Flask
    app.run(
        host=ServerConfig.HOST,
        port=ServerConfig.PORT,
        debug=False,
        threaded=True
    )