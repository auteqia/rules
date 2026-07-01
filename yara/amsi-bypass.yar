rule Hunt_AMSI_Memory_Patch_Payloads {
    meta:
        description = "Détecte les payloads (scripts/binaires) contenant les séquences d'octets typiques pour le byte patching de amsi.dll"
        author = "Ton Nom - Thèse MS UTT"
        date = "2026-07-01"
        context = "Analyse In-Memory / Chasse aux menaces Fileless"

    strings:
        // 1. Les Opcodes (Le cœur de l'attaque)
        // Ce sont les instructions assembleur injectées pour forcer l'arrêt du scan.
        $opcode_invalidarg = { B8 57 00 07 80 C3 } // mov eax, 0x80070057 ; ret (Code d'erreur E_INVALIDARG)
        $opcode_zeroret    = { 31 C0 C3 }          // xor eax, eax ; ret (Retourne 0 / AMSI_RESULT_CLEAN)
        $opcode_movzero    = { B8 00 00 00 00 C3 } // mov eax, 0 ; ret (Variante du retour à 0)
        $opcode_ret        = { C3 90 90 }          // ret ; nop ; nop (Arrêt brutal de la fonction)

        // 2. Les cibles (Ce que l'attaquant cherche en mémoire)
        $target_dll   = "amsi.dll" ascii wide nocase
        $target_func1 = "AmsiScanBuffer" ascii wide nocase
        $target_func2 = "AmsiOpenSession" ascii wide nocase

        // 3. Les vecteurs de modification mémoire (Comment l'attaquant rend la zone inscriptible)
        // Les attaquants doivent rendre la page mémoire RX (Read-Execute) en RWX ou RW pour patcher.
        $api_vp   = "VirtualProtect" ascii wide nocase
        $api_ntvp = "NtProtectVirtualMemory" ascii wide nocase

    condition:
        // La logique de détection : Intention + Cible + Arme
        
        // Condition A : Le fichier ou le dump mémoire mentionne l'AMSI
        $target_dll and any of ($target_func*) 
        
        and 
        
        // Condition B : Il y a une volonté de manipuler les droits mémoire
        any of ($api_*) 
        
        and 
        
        // Condition C : On retrouve les tableaux d'octets (opcodes) typiques d'un patch
        any of ($opcode_*)
}
