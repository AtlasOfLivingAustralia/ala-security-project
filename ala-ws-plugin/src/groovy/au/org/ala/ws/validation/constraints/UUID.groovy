package au.org.ala.ws.validation.constraints

import javax.validation.Constraint
import javax.validation.ConstraintValidator
import javax.validation.ConstraintValidatorContext
import javax.validation.Payload
import java.lang.annotation.ElementType
import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy
import java.lang.annotation.Target

@Target([ElementType.PARAMETER])
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UUIDValidator)
@interface UUID {
    String message() default '{au.org.ala.ws.validation.constraints.message}'

    Class<?>[] groups() default []

    Class<? extends Payload>[] payload() default []
}

class UUIDValidator implements ConstraintValidator<UUID, String> {

    static final UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

    @Override
    void initialize(UUID constraintAnnotation) {}

    @Override
    boolean isValid(String value, ConstraintValidatorContext context) {
        value =~ UUID_REGEX
    }
}