package org.zerock.mallapi.controller.formatter;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import org.springframework.format.Formatter;
import org.springframework.lang.NonNull;

public class LocalDateFormatter implements Formatter<LocalDate> {
    @Override
    @NonNull
    public LocalDate parse(@NonNull String text, @NonNull Locale locale) {
        return LocalDate.parse(text, DateTimeFormatter.ofPattern("yyyy-MM-dd", locale));
    }

    @Override
    @NonNull
    public String print(@NonNull LocalDate object, @NonNull Locale locale) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd", locale).format(object);
    }
}
