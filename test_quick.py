#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test rapide Andromède - Version simplifiée
"""

import sys
import time
from datetime import datetime

def test_quick():
    """Test rapide de tous les modules."""
    print("🚀 Test rapide Andromède")
    print("=" * 40)
    
    results = []
    start_time = time.time()
    
    # Test 1: Orion Core
    try:
        from core.ai.orion_core import OrionCore
        orion = OrionCore()
        analysis = orion.analyze_threat("test malware")
        results.append(("Orion Core", True))
        print("✅ Orion Core: OK")
    except Exception as e:
        results.append(("Orion Core", False))
        print(f"❌ Orion Core: {str(e)[:50]}")
    
    # Test 2: Pegasus Predict
    try:
        from core.ai.pegasus_predict import PegasusPredict
        pegasus = PegasusPredict("cpu")
        prediction = pegasus.predict_vulnerabilities("sql injection")
        results.append(("Pegasus Predict", True))
        print("✅ Pegasus Predict: OK")
    except Exception as e:
        results.append(("Pegasus Predict", False))
        print(f"❌ Pegasus Predict: {str(e)[:50]}")
    
    # Test 3: Gaia Generator
    try:
        from core.ai.gaia_generator import GaiaGenerator
        gaia = GaiaGenerator("cpu")
        decoys = gaia.generate_decoys("admin login")
        results.append(("Gaia Generator", True))
        print("✅ Gaia Generator: OK")
    except Exception as e:
        results.append(("Gaia Generator", False))
        print(f"❌ Gaia Generator: {str(e)[:50]}")
    
    # Test 4: Neural Sandbox
    try:
        from core.ai.neural_sandbox import NeuralSandbox
        sandbox = NeuralSandbox()
        stats = sandbox.get_sandbox_stats()
        results.append(("Neural Sandbox", True))
        print("✅ Neural Sandbox: OK")
    except Exception as e:
        results.append(("Neural Sandbox", False))
        print(f"❌ Neural Sandbox: {str(e)[:50]}")
    
    # Test 5: Astra Assistant
    try:
        from core.ai.astra_assistant import AstraAssistant
        astra = AstraAssistant()
        response = astra.chat("Qu'est-ce qu'un malware ?")
        results.append(("Astra Assistant", True))
        print("✅ Astra Assistant: OK")
    except Exception as e:
        results.append(("Astra Assistant", False))
        print(f"❌ Astra Assistant: {str(e)[:50]}")
    
    # Test 6: Andromeda Chain
    try:
        from core.blockchain.andromeda_chain import AndromedaChain
        chain = AndromedaChain()
        block_hash = chain.add_threat_signature({"threat_type": "malware", "hash": "abc123"})
        results.append(("Andromeda Chain", True))
        print("✅ Andromeda Chain: OK")
    except Exception as e:
        results.append(("Andromeda Chain", False))
        print(f"❌ Andromeda Chain: {str(e)[:50]}")
    
    # Test 7: Nebula Shield
    try:
        from core.shield.nebula_shield import NebulaShield
        shield = NebulaShield()
        shield.activate_protection()
        alert = shield.detect_intrusion("192.168.1.100", "suspicious")
        results.append(("Nebula Shield", True))
        print("✅ Nebula Shield: OK")
    except Exception as e:
        results.append(("Nebula Shield", False))
        print(f"❌ Nebula Shield: {str(e)[:50]}")
    
    # Test 8: Quantum Shield
    try:
        from core.quantum.quantum_shield import QuantumShield
        qshield = QuantumShield()
        encrypted = qshield.encrypt_data("test data")
        decrypted = qshield.decrypt_data(encrypted["ciphertext"], encrypted["key_id"])
        results.append(("Quantum Shield", True))
        print("✅ Quantum Shield: OK")
    except Exception as e:
        results.append(("Quantum Shield", False))
        print(f"❌ Quantum Shield: {str(e)[:50]}")
    
    # Test 9: StarMap Visualizer
    try:
        from ui.starmap_visualizer import StarMapVisualizer
        visualizer = StarMapVisualizer()
        threat_data = {"id": "test_threat", "name": "Test", "severity": "high"}
        visualizer.add_threat(threat_data)
        stats = visualizer.get_stats()
        results.append(("StarMap Visualizer", True))
        print("✅ StarMap Visualizer: OK")
    except Exception as e:
        results.append(("StarMap Visualizer", False))
        print(f"❌ StarMap Visualizer: {str(e)[:50]}")
    
    # Résultats finaux
    passed = sum(1 for _, success in results if success)
    total = len(results)
    success_rate = (passed / total) * 100
    execution_time = time.time() - start_time
    
    print("\n" + "=" * 40)
    print("📊 RÉSULTATS")
    print("=" * 40)
    print(f"✅ Tests réussis: {passed}/{total}")
    print(f"📈 Taux de réussite: {success_rate:.1f}%")
    print(f"⏱️ Temps: {execution_time:.2f}s")
    
    if success_rate == 100:
        print("\n🎉 PARFAIT! 100% DE RÉUSSITE!")
        print("🚀 Andromède est entièrement opérationnel!")
    elif success_rate >= 80:
        print("\n🎉 EXCELLENT! INTÉGRATION RÉUSSIE!")
        print("🚀 Andromède est opérationnel!")
    else:
        print("\n⚠️ Quelques ajustements nécessaires")
    
    return success_rate >= 80

if __name__ == "__main__":
    success = test_quick()
    sys.exit(0 if success else 1) 