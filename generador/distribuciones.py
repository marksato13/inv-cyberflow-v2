"""Muestreadores de ns-3 adaptados a random.Random de Python."""
from __future__ import annotations

import math


def lognormal_truncada(rng, media, desviacion, minimo, maximo):
    sigma2 = math.log1p((desviacion / media) ** 2)
    mu = math.log(media) - sigma2 / 2
    sigma = math.sqrt(sigma2)
    while True:
        v = int(rng.lognormvariate(mu, sigma))
        if minimo <= v < maximo:
            return v


def h1(rng):
    return lognormal_truncada(rng, 10710, 25032, 100, 2_000_000)


def h2(rng):
    return lognormal_truncada(rng, 7758, 126168, 50, 2_000_000)


def h3(rng):
    while True:
        x = int(2 / (1.0 - rng.random()) ** (1 / 1.1))
        if 2 <= x < 55:
            return x - 2


def f1(rng):
    while True:
        v = int(rng.lognormvariate(14.45, 0.35))
        if 0 < v < 5_000_000:
            return v


def pausa(rng, media, factor):
    return rng.expovariate(factor / media)


def parsing(rng):
    return rng.expovariate(1 / 0.13)
