import logging

logger = logging.getLogger(__name__)


def update_patient(patient_id: str, diagnosis: str, medication: str) -> None:
    # PRI003: health data (PHI) in log statements
    logger.info("Updating patient %s with diagnosis: %s", patient_id, diagnosis)

    # PRI003: medication in log
    logging.info("Patient medication: %s", medication)

    # PRI003: treatment in logger
    treatment = "chemotherapy"
    logger.debug("Patient treatment plan: %s", treatment)

    # PRI003: prescription logged
    prescription = "amoxicillin"
    logger.warning("New prescription written: %s", prescription)
