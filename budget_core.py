"""
Budget core: formule pure per il calcolo del budget e del risparmio.
"""
import calendar
from dataclasses import dataclass
from datetime import date


@dataclass
class RisultatoBudget:
    disponibile_lordo: float
    disponibile_netto: float
    pac_obiettivo: float
    cuscinetto: float
    disponibile_libero: float
    budget_giornaliero: float
    giorni_rimanenti: int
    pac_percentuale: float
    cuscinetto_percentuale: float
    in_rosso: bool
    risparmio_previsto_fine_ciclo: float


def calcola_budget(
    riporto_ciclo_prec: float,
    tot_entrate_ciclo: float,
    spese_fisse_ciclo_tot: float,
    spese_discrezionali_fatte: float,
    giorni_rimanenti: int,
    pac_percentuale: float = 0.10,
    cuscinetto_percentuale: float = 0.0,
    entrate_previste_fino_fine: float = 0.0,
    spese_previste_fino_fine: float = 0.0,
    spese_discrezionali_medie_giornaliere: float = 0.0,
    pac_fisso: float = 0.0,
    cuscinetto_fisso: float = 0.0,
) -> RisultatoBudget:
    disponibile_lordo = (
        riporto_ciclo_prec
        + tot_entrate_ciclo
        - spese_fisse_ciclo_tot
        - spese_discrezionali_fatte
    )

    if pac_fisso > 0:
        pac_obiettivo = max(0.0, min(disponibile_lordo, pac_fisso)) if disponibile_lordo > 0 else 0.0
    else:
        pac_obiettivo = max(0.0, disponibile_lordo * pac_percentuale)

    residuo_dopo_pac = max(0.0, disponibile_lordo - pac_obiettivo)
    if cuscinetto_fisso > 0:
        cuscinetto = min(residuo_dopo_pac, cuscinetto_fisso)
    else:
        cuscinetto = max(0.0, disponibile_lordo * cuscinetto_percentuale)

    disponibile_netto = max(0.0, disponibile_lordo - pac_obiettivo - cuscinetto)

    budget_giornaliero = disponibile_netto / giorni_rimanenti if giorni_rimanenti > 0 else 0.0

    spese_discrezionali_future_stimate = spese_discrezionali_medie_giornaliere * giorni_rimanenti
    lordo_previsto_fine_ciclo = (
        disponibile_lordo
        + entrate_previste_fino_fine
        - spese_previste_fino_fine
        - spese_discrezionali_future_stimate
    )
    if lordo_previsto_fine_ciclo >= 0:
        pac_fine = min(lordo_previsto_fine_ciclo, pac_fisso) if pac_fisso > 0 else (lordo_previsto_fine_ciclo * pac_percentuale)
        cusc_fine = min(max(0.0, lordo_previsto_fine_ciclo - pac_fine), cuscinetto_fisso) if cuscinetto_fisso > 0 else (lordo_previsto_fine_ciclo * cuscinetto_percentuale)
        risparmio_previsto = min(lordo_previsto_fine_ciclo, pac_fine + cusc_fine)
    else:
        risparmio_previsto = lordo_previsto_fine_ciclo

    return RisultatoBudget(
        disponibile_lordo=disponibile_lordo,
        disponibile_netto=disponibile_netto,
        pac_obiettivo=pac_obiettivo,
        cuscinetto=cuscinetto,
        disponibile_libero=disponibile_netto,
        budget_giornaliero=budget_giornaliero,
        giorni_rimanenti=giorni_rimanenti,
        pac_percentuale=pac_percentuale,
        cuscinetto_percentuale=cuscinetto_percentuale,
        in_rosso=(disponibile_lordo < 0),
        risparmio_previsto_fine_ciclo=risparmio_previsto,
    )


def calcola_data_addebito_cc(
    metodo: str,
    data_acquisto: date,
    carte_cfg: dict | None = None,
) -> date:
    if carte_cfg and metodo in carte_cfg:
        regola = carte_cfg[metodo]
        cutoff = int(regola.get("cutoff", 15))
        addebito = int(regola.get("addebito", 0))
        mesi_avanti = 0 if data_acquisto.day <= cutoff else 1
        mese = data_acquisto.month + mesi_avanti
        anno = data_acquisto.year
        while mese > 12:
            mese -= 12
            anno += 1
        ultimo = calendar.monthrange(anno, mese)[1]
        giorno_eff = ultimo if addebito <= 0 else min(addebito, ultimo)
        return date(anno, mese, giorno_eff)
    if metodo == "Visa":
        mesi_avanti = 0 if data_acquisto.day <= 2 else 1
        mese = data_acquisto.month + mesi_avanti
        anno = data_acquisto.year
        while mese > 12:
            mese -= 12
            anno += 1
        ultimo = calendar.monthrange(anno, mese)[1]
        return date(anno, mese, min(12, ultimo))
    if metodo == "AmEx":
        mesi_avanti = 0 if data_acquisto.day <= 16 else 1
        mese = data_acquisto.month + mesi_avanti
        anno = data_acquisto.year
        while mese > 12:
            mese -= 12
            anno += 1
        ultimo = calendar.monthrange(anno, mese)[1]
        return date(anno, mese, ultimo)
    return data_acquisto
