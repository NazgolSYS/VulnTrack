from app.services.risk_service import calculate_risk

result = calculate_risk(likelihood=4, impact=5)

print(result)