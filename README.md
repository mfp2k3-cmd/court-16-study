# Court 16 — estudo de port para Windows

Projeto comunitário de estudo para executar uma cópia legítima de NBA LIVE 16 no Windows. O runtime desta versão é integrado ao shadPS4; este projeto não contém o jogo nem substitui a necessidade do dump do usuário.

**Versão:** V1.00-C

## Requisitos

- Windows x64
- Dump próprio de NBA LIVE 16, CUSA01933
- Módulos de firmware obtidos da própria instalação PS4, colocados em `user/sys_modules`
- GPU e drivers compatíveis com Vulkan

## Executar

Extraia o arquivo do Release para uma pasta gravável, abra `Court 16 Launcher.exe` e selecione a pasta do dump. A primeira execução criará as configurações locais. Consulte `LEIA-ME.txt` e `user/sys_modules/LEIA-ME-MODULOS.txt` no pacote.

## Menu durante o jogo

- Abra o menu pelo botão central PS/Guide do controle, ou mantenha Start e Select/Back pressionados juntos por 2 segundos.
- Use o direcional para escolher; X/A confirma e Círculo/B volta.
- No menu, alterne a exibição de FPS e o FSR 1. A opção de resolução alterna o tamanho de saída da janela entre 720p, 1080p, 1440p e 4K.

## Atualização V1.00-C

O menu do jogo foi ampliado e recebeu controles para resolução da janela e ativação/desativação do FSR 1 durante a partida.

## Compilar

O código-fonte correspondente está neste repositório. Clone incluindo o submódulo fixado:

```powershell
git clone --recurse-submodules https://github.com/mfp2k3-cmd/court-16-study.git
cd court-16-study
.\PREPARAR-E-COMPILAR.ps1
```

O script usa o snapshot shadPS4 registrado em `.gitmodules`, aplica os patches incluídos em `patches/shadps4` e compila o launcher/runtime. Veja `LEIA-ME-FONTES.txt` para os requisitos do toolchain.

## Licenças

O runtime shadPS4 é distribuído sob GPL-2.0-or-later. Os patches deste projeto e os avisos e textos de licença das dependências acompanham o código e o Release. Consulte `LICENSE`, `LICENSES/` e `THIRD-PARTY-NOTICES.txt`.

## Marcas e afiliação

Projeto independente de estudo, sem afiliação, patrocínio ou aprovação da EA, NBA ou Sony. Os nomes dos jogos e plataformas identificam apenas a compatibilidade pretendida. O usuário deve fornecer seu próprio dump e arquivos de firmware.

## Reconhecimento

Os estudos de arquitetura, análise e evolução do código contaram com assistência do OpenAI Codex.

