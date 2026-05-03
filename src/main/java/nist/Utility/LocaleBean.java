package nist.Utility;

import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Named;

import java.io.Serializable;
import java.util.Locale;

/**
 * Managed bean for handling user locale preferences in a JSF session.
 * This bean allows switching the language dynamically for the user interface.
 *
 * <p>Uses English as the default language. Locale changes are applied to the
 * current {@link jakarta.faces.component.UIViewRoot}.</p>
 *
 * @author Aman Utkarsh and Tarun Kumar
 * @version 1.0
 * @since 2024-05-01
 */
@Named("localeBean")
@SessionScoped
public class LocaleBean implements Serializable {

    /**
     * The current locale of the user session. Default is English.
     */
    private Locale locale = Locale.ENGLISH;

    /**
     * Returns the current {@link Locale} of the session.
     *
     * @return the current locale
     */
    public Locale getLocale() {
        return locale;
    }

    /**
     * Returns the language code of the current locale.
     *
     * @return a language string, e.g., "en" or "es"
     */
    public String getLanguage() {
        return locale.getLanguage();
    }

    /**
     * Sets a new language for the session and updates the view root locale.
     *
     * @param language the ISO language code to set (e.g., "en", "es")
     */
    public void setLanguage(String language) {
        this.locale = new Locale(language);
        FacesContext.getCurrentInstance().getViewRoot().setLocale(locale);
    }
}
