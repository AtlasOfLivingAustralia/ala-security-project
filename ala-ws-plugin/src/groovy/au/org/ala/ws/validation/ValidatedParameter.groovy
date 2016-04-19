package au.org.ala.ws.validation

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target([ElementType.PARAMETER])
public @interface ValidatedParameter {
    String paramName()

    Class paramType()
}