package com.gallifrey.authenticator.input

import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement

/** How the user reproduces the pattern. Both feed the same entry buffer. */
enum class InputMode {
    /** Two explicit Dot and Dash controls. Initial mode for TalkBack users. */
    BUTTONS,

    /** A single tap/hold area classified by hold duration. Optional, after practice. */
    GESTURE,
}

/**
 * Collects the user's reproduction of a pattern before it is submitted.
 *
 * Switching mode keeps the current entry. reset() clears only the entry, it
 * never touches the transaction's failure count (that lives in
 * TransactionGuard). Progress is exposed as a count only, so feedback never
 * has to speak the sequence itself.
 */
class PatternInput(
    private val expectedLength: Int = HapticPattern.DEFAULT_LENGTH,
    private var classifier: GestureClassifier = GestureClassifier(),
    mode: InputMode = InputMode.BUTTONS,
) {
    init {
        require(expectedLength > 0) { "expectedLength must be positive" }
    }

    private val entered = ArrayList<PatternElement>(expectedLength)

    var mode: InputMode = mode
        private set

    /** Number of removeLast() calls, recorded as usability evidence. */
    var corrections: Int = 0
        private set

    val count: Int get() = entered.size
    val isComplete: Boolean get() = entered.size == expectedLength
    val isEmpty: Boolean get() = entered.isEmpty()

    fun switchMode(newMode: InputMode) {
        mode = newMode
    }

    /** Applies a recalibrated hold threshold without losing the entry. */
    fun updateClassifier(newClassifier: GestureClassifier) {
        classifier = newClassifier
    }

    /** Alternative Dot button. Returns false if the entry is already full. */
    fun addDot(): Boolean = add(PatternElement.DOT)

    /** Alternative Dash button. Returns false if the entry is already full. */
    fun addDash(): Boolean = add(PatternElement.DASH)

    /**
     * Hold gesture. Returns the classified element, or null if the touch was
     * cancelled or the entry is already full (nothing is added in either case).
     */
    fun addGesture(pressedAtMs: Long, releasedAtMs: Long, cancelled: Boolean = false): PatternElement? {
        val element = classifier.classify(pressedAtMs, releasedAtMs, cancelled) ?: return null
        return if (add(element)) element else null
    }

    /** Removes the last element. Returns false if there was nothing to remove. */
    fun removeLast(): Boolean {
        if (entered.isEmpty()) return false
        entered.removeAt(entered.lastIndex)
        corrections++
        return true
    }

    /** Clears the entry only (the "reset" control). */
    fun reset() {
        entered.clear()
    }

    /** The entered pattern, or null while it is incomplete. */
    fun toPattern(): HapticPattern? = if (isComplete) HapticPattern(entered) else null

    override fun toString(): String = "PatternInput(count=$count/$expectedLength, mode=$mode)"

    private fun add(element: PatternElement): Boolean {
        if (isComplete) return false
        entered += element
        return true
    }
}
