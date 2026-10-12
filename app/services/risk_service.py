
def calculate_risk(likelihood: int, impact: int) -> dict:
    """
    Calculate a risk score and assign a risk level.

    Likelihood and impact must each be between 1 and 5.
    """

    if not 1 <= likelihood <= 5:
        raise ValueError("Likelihood must be between 1 and 5.")

    if not 1 <= impact <= 5:
        raise ValueError("Impact must be between 1 and 5.")

    risk_score = likelihood * impact

    if risk_score <= 4:
        risk_level = "low"
    elif risk_score <= 9:
        risk_level = "medium"
    elif risk_score <= 15:
        risk_level = "high"
    else:
        risk_level = "critical"

    return {
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


