"""Comprobaciones estadísticas de los muestreadores v3."""
import math
import random
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generador"))
import distribuciones as d


N = 200_000


def normal(x):
    return (1 + math.erf(x / math.sqrt(2))) / 2


def cdf_lognormal_entera(x, mu, sigma, minimo, maximo):
    def f(y):
        return normal((math.log(y) - mu) / sigma)
    return (f(x + 1) - f(minimo)) / (f(maximo) - f(minimo))


def ks(datos, mu, sigma, minimo, maximo):
    datos.sort()
    n = len(datos)
    mayor = 0
    for i, x in enumerate(datos, 1):
        c = cdf_lognormal_entera(x, mu, sigma, minimo, maximo)
        mayor = max(mayor, abs(i / n - c), abs((i - 1) / n - c))
    return mayor


class TestDistribuciones(unittest.TestCase):
    def test_lognormales_truncadas(self):
        for nombre, funcion, media, des, minimo, maximo in (
                ("H1", d.h1, 10710, 25032, 100, 2_000_000),
                ("H2", d.h2, 7758, 126168, 50, 2_000_000)):
            with self.subTest(nombre=nombre):
                rng = random.Random(20261125)
                datos = [funcion(rng) for _ in range(N)]
                self.assertTrue(all(minimo <= x < maximo for x in datos))
                s2 = math.log1p((des / media) ** 2)
                mu = math.log(media) - s2 / 2
                self.assertLess(ks(datos, mu, math.sqrt(s2), minimo, maximo), .01)
        rng = random.Random(20261125)
        datos = [d.f1(rng) for _ in range(N)]
        self.assertTrue(all(0 < x < 5_000_000 for x in datos))
        self.assertLess(ks(datos, 14.45, .35, 1, 5_000_000), .01)

    def test_pareto_por_entero(self):
        rng = random.Random(20261125)
        frec = Counter(d.h3(rng) for _ in range(N))
        self.assertTrue(all(0 <= x <= 52 for x in frec))
        normalizador = 1 - (2 / 55) ** 1.1
        for x in range(2, 55):
            prob = ((2 / x) ** 1.1 - (2 / (x + 1)) ** 1.1) / normalizador
            if prob >= .01:
                self.assertLess(abs(frec[x - 2] / N - prob) / prob, .05, x)

    def test_exponenciales(self):
        rng = random.Random(20261125)
        for media, factor in ((30, 1), (30, 1 / 3), (30, 2), (180, 1)):
            datos = [d.pausa(rng, media, factor) for _ in range(N)]
            self.assertLess(abs(sum(datos) / N - media / factor) / (media / factor), .01)
        datos = [d.parsing(rng) for _ in range(N)]
        self.assertLess(abs(sum(datos) / N - .13) / .13, .01)


if __name__ == "__main__":
    unittest.main()
