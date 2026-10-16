#!/usr/bin/env python3
"""Render the repository diagrams without network access or a JavaScript runtime.

SVG uses standard-library Python; PNG export uses Inkscape. The accompanying
Mermaid files describe the same component relationships and sequence semantics.
"""
from __future__ import annotations

import argparse
import html
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
BG = '#F5F7FB'
INK = '#152B43'
MUTED = '#52667C'
BORDER = '#D6E0EA'
BLUE = '#147CAA'
PURPLE = '#7455B7'
GREEN = '#247C66'
AMBER = '#A56110'
RED = '#A5454A'
FONT = 'DejaVu Sans, sans-serif'

class Canvas:
    def __init__(self, width, height, title, description):
        self.width, self.height = width, height
        self.parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">', f'<title id="title">{html.escape(title)}</title><desc id="desc">{html.escape(description)}</desc>', '<defs>']
        for name, color in [('ink', INK), ('blue', BLUE), ('purple', PURPLE), ('green', GREEN), ('amber', AMBER), ('red', RED), ('muted', MUTED)]:
            self.parts.append(f'<marker id="arrow-{name}" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto" markerUnits="userSpaceOnUse"><path d="M 0 0 L 9 5 L 0 10 z" fill="{color}"/></marker>')
        self.parts.append('</defs>')
        self.rect(0,0,width,height,BG,rx=0)
    def rect(self,x,y,w,h,fill='white',stroke=None,rx=20,sw=1.5,dash=None):
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"'+(f' stroke="{stroke}" stroke-width="{sw}"' if stroke else '')+(f' stroke-dasharray="{dash}"' if dash else '')+'/>')
    def text(self,x,y,text,size=24,color=INK,weight=400,anchor='start'):
        self.parts.append(f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" fill="{color}" font-weight="{weight}" text-anchor="{anchor}">{html.escape(str(text))}</text>')
    def lines(self,x,y,lines,size=24,color=INK,weight=400,lh=None,anchor='start'):
        for i,line in enumerate(lines): self.text(x,y+i*(lh or size*1.45),line,size,color,weight,anchor)
    def line(self,x1,y1,x2,y2,color=MUTED,sw=2,dash=None,arrow=None):
        self.parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}"'+(f' stroke-dasharray="{dash}"' if dash else '')+(f' marker-end="url(#arrow-{arrow})"' if arrow else '')+'/>')
    def path(self,d,color=MUTED,sw=2,dash=None,arrow=None):
        self.parts.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}" stroke-linejoin="round"'+(f' stroke-dasharray="{dash}"' if dash else '')+(f' marker-end="url(#arrow-{arrow})"' if arrow else '')+'/>')
    def circle(self,x,y,r,fill,stroke=None):
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}"'+(f' stroke="{stroke}"' if stroke else '')+'/>')
    def pill(self,x,y,w,label,fill,color,size=18):
        self.rect(x,y,w,36,fill,rx=18)
        self.text(x+w/2,y+25,label,size,color,600,anchor='middle')
    def save(self,name):
        p=HERE/f'{name}.svg'; p.write_text('\n'.join(self.parts+['</svg>'])+'\n',encoding='utf-8'); return p


def high_level():
    c=Canvas(1500,1040,'LLM-AVChain: de un incidente local a una defensa compartida','Un nodo A recoge un incidente y propone una respuesta con un LLM. El centro valida y firma conocimiento versionado. El nodo B comprueba su variante y aplica solo acciones aprobadas localmente. Resultados y fallos vuelven como evidencia.')
    c.pill(60,40,200,'VISIÓN GENERAL','#E5EAF4',MUTED)
    c.text(60,129,'De un incidente local',46,weight=700)
    c.text(60,185,'a una defensa compartida',46,weight=700)
    c.text(60,230,'El conocimiento viaja; el permiso de actuar es local.',25,MUTED)
    cards=[(60,BLUE,'#E5F3FA','1','EQUIPO A','Observa y propone', ['Recoge señales del incidente.','La IA del equipo propone','un plan de respuesta.'],['Los archivos y el texto externo','son información por comprobar.']),
           (550,PURPLE,'#EFEAFA','2','CENTRO COMPARTIDO','Valida y conserva',['Comprueba las aprobaciones.','Comparte la respuesta validada','y conserva su historial.'],['La propuesta del modelo por sí','sola no autoriza una acción.']),
           (1040,GREEN,'#E5F3ED','3','EQUIPO B','Adapta y comprueba',['Reutiliza la resolución y la','adapta a una variante local.','Ejecuta solo acciones permitidas.'],['Verifica el resultado; si falla,','intenta restaurar el estado previo.'])]
    for x,col,tint,num,label,title,body,note in cards:
        c.rect(x,285,400,390,'white',BORDER)
        c.rect(x,285,400,10,col,rx=0)
        c.circle(x+44,337,23,tint)
        c.text(x+44,345,num,23,col,700,'middle')
        c.text(x+80,344,label,19,col,700)
        c.text(x+28,402,title,26,weight=700)
        c.lines(x+28,450,body,22,lh=34)
        c.line(x+28,545,x+372,545,BORDER)
        c.lines(x+28,587,note,18,MUTED,lh=28)
    c.line(470,480,537,480,PURPLE,sw=3,arrow='purple')
    c.line(960,480,1027,480,GREEN,sw=3,arrow='green')
    c.text(504,446,'evidencia',16,MUTED,anchor='middle')
    c.text(994,446,'resolución',16,MUTED,anchor='middle')
    # Feedback keeps the outcome distinct from an automatically approved update.
    c.path('M 1240 675 L 1240 728 L 750 728 L 750 675',GREEN,sw=2.5,dash='8 6',arrow='green')
    c.rect(880,710,297,35,BG,rx=0)
    c.text(1028,734,'Resultado + nueva evidencia',18,GREEN,600,'middle')
    c.rect(60,777,1380,170,'#EAF0F7',rx=20)
    c.pill(85,797,176,'EJEMPLO', '#D8E4F0', MUTED, 17)
    c.text(282,824,'Una falsa entrevista solicita ejecutar un repositorio.',24,weight=600)
    c.lines(86,870,['A detecta el patrón → el centro valida la respuesta → B reconoce otra variante.',
                     'El mismo recorrido admite otros incidentes; este es solo un caso de demostración.'],23,MUTED,lh=35)
    c.text(60,999,'PoC acotada · las pruebas controladas no equivalen a protección en producción.',19,MUTED)
    c.save('01_incident_learning_overview_es')



def components():
    c=Canvas(1920,1460,'LLM-AVChain: componentes y límites de confianza','Flujo de datos y controles del recorrido de incidentes: recogida acotada, inferencia local no confiable, aprobación firmada, almacén versionado y ejecución local tipada con restauración ante fallo.')
    c.pill(60,35,235,'VISTA TÉCNICA · 1/2','#E5EAF4',MUTED)
    c.text(60,122,'Componentes y límites de confianza',44,weight=700)
    c.text(60,170,'Flujo de datos y controles del recorrido de incidentes',25,MUTED)
    c.rect(60,214,1800,105,'#FFF3E2','#EAD0AE')
    c.text(90,257,'ENTRADAS SIN CONFIANZA',20,AMBER,700)
    c.text(90,293,'Archivos, eventos y texto externo son evidencia; sus instrucciones no conceden permisos.',25,INK)
    c.line(320,319,320,375,AMBER,sw=2.5,arrow='amber')
    c.line(1600,319,1600,375,AMBER,sw=2.5,arrow='amber')
    groups=[(60,520,BLUE,'#E5F3FA','NODO A','Primera observación'),(660,600,PURPLE,'#EFEAFA','CENTRO COMPARTIDO','Validación y persistencia'),(1340,520,GREEN,'#E5F3ED','NODO B','Variante y acción local')]
    for x,w,col,tint,label,subtitle in groups:
        c.rect(x,375,w,738,tint,col,sw=1.2)
        c.text(x+28,416,label,21,col,700)
        c.text(x+28,449,subtitle,21,MUTED)
    def box(x,y,w,h,title,lines,col):
        c.rect(x,y,w,h,'white',BORDER,rx=14)
        c.text(x+22,y+38,title,24,col,700)
        c.lines(x+22,y+77,lines,21,lh=31)
    box(84,480,472,140,'IncidentCollector',['Raíz permitida · lectura acotada','Evidencia y hashes'],BLUE)
    box(84,665,472,166,'IncidentTriage',['LLM local + catálogo autorizado','Enlaza evidencia con IDs existentes','No crea código, permisos ni firmas'],BLUE)
    box(84,876,472,174,'RemediationPackage',['Borrador del operador/catálogo','Con evidencia y análisis del nodo A','Versión · vigencia · acciones fijas'],BLUE)
    c.line(320,620,320,652,BLUE,arrow='blue')
    c.line(320,831,320,863,BLUE,arrow='blue')
    c.text(340,856,'enriquece',16,BLUE)
    box(684,480,552,140,'ValidatorApproval',['Validadores de confianza','Firmas Ed25519 sobre el paquete'],PURPLE)
    box(684,665,552,166,'KnowledgeStore',['Quórum + firmas + caducidad','Revocación + versión monotónica','Entrada confirmed + evidencia'],PURPLE)
    box(684,876,552,174,'Ledger SQL + evidencia',['Paquete aprobado y evidencia vinculada','Historial auditable de decisiones','Persistencia del repositorio existente'],PURPLE)
    c.line(960,620,960,652,PURPLE,arrow='purple')
    c.line(960,831,960,863,PURPLE,arrow='purple')
    box(1364,480,472,166,'IncidentNode',['KnowledgeClient: firma + versión','IncidentTriage: bindings locales','Sin acciones nuevas ni código'],GREEN)
    box(1364,691,472,140,'LocalApproval',['Incidente · paquete · bindings · raíz','Caducidad; externa al modelo'],GREEN)
    box(1364,876,472,174,'ScopedExecutor',['disable_npm_hook / quarantine_file','Precheck → aplicar → postcheck','Hashes exactos · journal local'],GREEN)
    c.line(1600,646,1600,678,GREEN,arrow='green')
    c.line(1600,831,1600,863,GREEN,arrow='green')
    c.path('M 556 965 L 608 965 L 608 550 L 670 550',PURPLE,sw=2.5,arrow='purple')
    c.path('M 1236 748 L 1300 748 L 1300 562 L 1351 562',GREEN,sw=2.5,arrow='green')
    c.rect(580,698,56,90,BG,rx=10)
    c.text(608,730,'plan',18,PURPLE,600,'middle')
    c.text(608,757,'vN',18,PURPLE,600,'middle')
    c.rect(1273,621,53,62,BG,rx=10)
    c.text(1300,648,'vN',18,GREEN,600,'middle')
    c.text(1300,671,'✓',20,GREEN,600,'middle')
    c.path('M 1510 1050 L 1510 1084 L 1110 1084 L 1110 1050',GREEN,sw=2,dash='7 5',arrow='green')
    c.rect(1163,1067,271,34,'#E5F3ED',rx=0)
    c.text(1298,1091,'Resultado + evidencia',19,GREEN,600,'middle')
    c.rect(60,1154,1200,182,'white',BORDER)
    c.text(88,1199,'DOS AUTORIZACIONES DISTINTAS',20,weight=700)
    c.lines(88,1243,['La aprobación central permite compartir conocimiento.',
                     'La aprobación local autoriza una actuación concreta en ese nodo.',
                     'El LLM no firma aprobaciones ni decide permisos.'],23,MUTED,lh=34)
    c.rect(1340,1154,520,182,'#FFF3E2','#EAD0AE')
    c.text(1368,1199,'SI FALLA LA COMPROBACIÓN',20,AMBER,700)
    c.lines(1368,1243,['Intentar restaurar el estado previo.',
                       'Guardar también fallos de rollback.',
                       'No declarar éxito sin postcheck.'],22,lh=34)
    c.line(1600,1113,1600,1141,AMBER,arrow='amber')
    c.text(60,1402,'Alcance: PoC local controlada. El backend LLM real y cada acción deben acreditarse con su evidencia de ejecución.',21,MUTED)
    c.save('02_incident_components_es')


def sequence():
    c=Canvas(1920,1880,'LLM-AVChain: secuencia del incidente a la acción local','Secuencia lógica: el nodo A crea conocimiento aprobado, el nodo B consulta una versión vigente y adapta una variante, una aprobación local autoriza acciones fijas; el ejecutor comprueba, revierte ante fallo y devuelve evidencia.')
    c.pill(60,35,235,'VISTA TÉCNICA · 2/2','#E5EAF4',MUTED)
    c.text(60,121,'Del incidente a una acción local verificable',43,weight=700)
    c.text(60,169,'Secuencia lógica del recorrido · no presupone despliegue distribuido ni inferencia real',24,MUTED)
    xs=[170,490,830,1170,1500,1790]
    roles=[('Nodo A','IncidentNode',BLUE,'#E5F3FA'),('LLM local','A y B',BLUE,'#E5F3FA'),('Centro compartido','KnowledgeStore',PURPLE,'#EFEAFA'),('Nodo B','IncidentNode',GREEN,'#E5F3ED'),('Permiso local','LocalApproval',AMBER,'#FFF3E2'),('Ejecutor local','ScopedExecutor',GREEN,'#E5F3ED')]
    for x,(name,sub,col,tint) in zip(xs,roles):
        w=250 if x!=1790 else 230
        c.rect(x-w/2,219,w,84,tint,col,rx=12)
        c.text(x,253,name,21,col,700,'middle')
        c.text(x,281,sub,18,MUTED,anchor='middle')
        c.line(x,304,x,1724,BORDER,sw=2,dash='6 7')
    def phase(y,n,label):
        c.rect(50,y,1815,40,'#E4EBF4',rx=10)
        c.text(70,y+27,f'{n}. {label}',21,INK,700)
    def arrow(a,b,y,label,col=INK,dashed=False,size=21,lines=None):
        c.line(xs[a],y,xs[b],y,col,sw=2.3,dash='8 5' if dashed else None,arrow={INK:'ink',BLUE:'blue',PURPLE:'purple',GREEN:'green',AMBER:'amber'}[col])
        if lines:
            c.lines((xs[a]+xs[b])/2,y-38,lines,size,col,lh=26,anchor='middle')
        else: c.text((xs[a]+xs[b])/2,y-13,label,size,col,anchor='middle')
    phase(335,'1','Crear conocimiento validado')
    c.text(70,403,'Catálogo previo del operador',20,MUTED)
    arrow(0,1,467,'',BLUE,size=19,lines=['Evidencia no confiable','+ catálogo de acciones'])
    arrow(1,0,528,'Bindings propuestos',BLUE,True,size=20)
    arrow(0,2,583,'Paquete + evidencia de A + firmas de validadores',PURPLE,size=21)
    c.rect(680,611,590,79,'#EFEAFA',BORDER,rx=12)
    c.text(702,641,'Verificar quórum, Ed25519, TTL y versión.',21,PURPLE,600)
    c.text(702,672,'Persistir paquete aprobado + evidencia.',21,PURPLE)
    phase(720,'2','Reutilizar la resolución en otra variante')
    arrow(3,2,810,'Consultar paquete vigente',PURPLE,size=20)
    arrow(2,3,868,'Paquete verificado vN',PURPLE,True,size=20)
    arrow(3,1,929,'Evidencia de variante + IDs de acción aprobados',GREEN,size=21)
    arrow(1,3,987,'Mapeo local; sin acciones nuevas',BLUE,True,size=21)
    phase(1030,'3','Autorizar, ejecutar y comprobar en el nodo B')
    arrow(3,4,1120,'',AMBER,size=20,lines=['Plan y alcance local','+ hashes exactos'])
    arrow(4,3,1181,'Autorización del plan',AMBER,True,size=20)
    arrow(3,2,1240,'Revalidar antes de escribir',PURPLE,size=19)
    arrow(3,5,1305,'Ejecutar plan validado',GREEN,size=21)
    c.rect(1340,1332,525,80,'#E5F3ED',BORDER,rx=12)
    c.text(1360,1364,'Precheck → acción tipada → postcheck',21,GREEN,600)
    c.text(1360,1395,'Sin shell ni código generado por el modelo.',20,GREEN)
    c.rect(1107,1436,758,150,'white',BORDER,rx=12)
    c.pill(1125,1452,119,'RESULTADO','#E5EAF4',MUTED,15)
    c.text(1266,1478,'Postcheck correcto: éxito verificable.',21,GREEN,600)
    c.line(1127,1502,1844,1502,BORDER)
    c.text(1127,1534,'Si falla tras el cambio: intentar restaurar y registrar',21,AMBER)
    c.text(1127,1565,'también el resultado de la restauración.',21,AMBER)
    arrow(5,3,1639,'Resultado + estado del rollback, si procede',GREEN,True,size=20)
    arrow(3,2,1709,'Resultado + evidencia',GREEN,size=20)
    c.rect(60,1762,1800,65,'#EAF0F7',rx=14)
    c.text(84,1803,'El feedback no aprueba una nueva versión. Los dobles de prueba no demuestran una inferencia LLM real.',23,MUTED)
    c.save('03_incident_sequence_es')

def main():
    p=argparse.ArgumentParser(); p.add_argument('--svg-only', action='store_true'); args=p.parse_args()
    high_level()
    components()
    sequence()
    if not args.svg_only:
        binary=shutil.which('inkscape')
        if not binary: raise SystemExit('Inkscape is required for PNG export; use --svg-only to generate SVG.')
        for svg in sorted(HERE.glob('0[1-3]_*.svg')):
            subprocess.run([binary,str(svg),'--export-type=png','--export-filename='+str(svg.with_suffix('.png'))],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

if __name__=='__main__': main()
