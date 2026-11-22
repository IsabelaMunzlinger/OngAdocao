package bdTrabalho.OngAplication.security;

import java.util.Set;

public final class RoleUtil {

    public static final String SESS_USER_ID = "USER_INTERNAL_ID";
    public static final String SESS_CREATED_AT = "SESSION_CREATED_AT";

    private RoleUtil() {}

    private static final Set<String> ROLES_VALIDAS = Set.of("admin", "user", "adotante");

    /**
     * Role vinda do claim `role` do ID Token JÁ VALIDADO. Só aceita valores de uma lista fixa;
     * qualquer outra coisa (ou ausência) cai no menor privilégio: "adotante".
     */
    public static String fromVerifiedClaim(String claim) {
        String r = claim == null ? "" : claim.trim().toLowerCase();
        return ROLES_VALIDAS.contains(r) ? r : "adotante";
    }

    /** "admin" -> "ROLE_ADMIN"; vazio -> "ROLE_ADOTANTE". */
    public static String toSpringRole(String role) {
        String r = (role == null || role.isBlank()) ? "ADOTANTE" : role.trim().toUpperCase();
        return r.startsWith("ROLE_") ? r : "ROLE_" + r;
    }
}
