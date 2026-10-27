# Court 16 — estudo de port para Windows

Projeto comunitário de estudo para executar uma cópia legítima de NBA LIVE 16 no Windows. O runtime desta versão é integrado ao shadPS4; este projeto não contém o jogo nem substitui a necessidade do dump do usuário.

**Versão em preparação:** V1.00-b (beta)

## Requisitos

- Windows x64
- Dump próprio de NBA LIVE 16, CUSA01933
- Módulos de firmware obtidos da própria instalação PS4, colocados em `user/sys_modules`
- GPU e drivers compatíveis com Vulkan

## Executar

Extraia o arquivo do Release para uma pasta gravável, abra `Court 16 Launcher.exe` e selecione a pasta do dump. A primeira execução criará as configurações locais. Consulte `LEIA-ME.txt` e `user/sys_modules/LEIA-ME-MODULOS.txt` no pacote.

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


