package com.gallifrey.authenticator.practice

import com.gallifrey.authenticator.haptics.PatternElement
import com.gallifrey.authenticator.haptics.PatternGenerator
import com.gallifrey.authenticator.input.InputMode
import com.gallifrey.authenticator.verify.LocalState
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PracticeSessionTest {

    private var now = 5_000_000L
    private val session = PracticeSession(clock = { now })

    private fun enter(elements: List<PatternElement>) = elements.forEach { session.addElement(it) }

    private fun enterCorrect() = enter(session.patternForPlayback().elements)

    private fun enterWrong() = enter(session.patternForPlayback().elements.map {
        if (it == PatternElement.DOT) PatternElement.DASH else PatternElement.DOT
    })

    @Test
    fun `correct entry needs explicit approval`() {
        enterCorrect()
        assertEquals(SubmitOutcome.Matched, session.submit())
        assertEquals(LocalState.AWAITING_APPROVAL, session.state)
        assertTrue(session.canApprove)
        session.recordDecision(approved = true)
        assertEquals(LocalState.APPROVED, session.state)
    }

    @Test
    fun `wrong entries count down and lock after three`() {
        enterWrong()
        assertEquals(SubmitOutcome.Mismatch(2), session.submit())
        assertEquals(0, session.input.count)
        enterWrong()
        assertEquals(SubmitOutcome.Mismatch(1), session.submit())
        enterWrong()
        assertEquals(SubmitOutcome.Locked, session.submit())
        assertEquals(LocalState.LOCKED, session.state)
        assertFalse(session.addDot())
        assertFalse(session.canApprove)
    }

    @Test
    fun `incomplete entry is not counted`() {
        session.addDot()
        assertEquals(SubmitOutcome.Incomplete(4, 1), session.submit())
        assertEquals(3, session.attemptsRemaining)
        assertEquals(0, session.stats().submissions)
    }

    @Test
    fun `mismatch after an earlier failure is still acknowledged so approval works`() {
        enterWrong()
        session.submit()
        enterCorrect()
        session.submit()
        assertTrue(session.canApprove)
    }

    @Test
    fun `expiry stops entry`() {
        now += PracticeSession.DEFAULT_EXPIRY_MS
        assertEquals(LocalState.EXPIRED, session.state)
        assertFalse(session.addDot())
        assertIs<SubmitOutcome.NotAccepting>(session.submit())
    }

    @Test
    fun `reset clears entry but not attempts`() {
        enterWrong()
        session.submit()
        session.addDot()
        session.resetEntry()
        assertEquals(0, session.input.count)
        assertEquals(2, session.attemptsRemaining)
    }

    @Test
    fun `deny is available before matching`() {
        assertTrue(session.canDeny)
        session.recordDecision(approved = false)
        assertEquals(LocalState.DENIED, session.state)
    }

    @Test
    fun `approve without a match is refused`() {
        assertFailsWith<IllegalStateException> { session.recordDecision(approved = true) }
    }

    @Test
    fun `direct approval skips pattern entry`() {
        assertTrue(session.chooseDirectApproval())
        assertTrue(session.canApprove)
        assertFalse(session.canEnter)
    }

    @Test
    fun `restart gives a fresh round and keeps the input mode`() {
        session.switchMode(InputMode.GESTURE)
        enterWrong(); session.submit()
        enterWrong(); session.submit()
        enterWrong(); session.submit()
        session.restart()
        assertEquals(LocalState.AWAITING_PATTERN, session.state)
        assertEquals(3, session.attemptsRemaining)
        assertEquals(InputMode.GESTURE, session.input.mode)
    }

    @Test
    fun `restart generates a new pattern`() {
        // A fixed-seed generator makes "different pattern" deterministic.
        val seeded = SecureRandom.getInstance("SHA1PRNG").apply { setSeed(42L) }
        val s = PracticeSession(generator = PatternGenerator(seeded), clock = { now })
        val seen = HashSet<List<PatternElement>>()
        repeat(20) { seen += s.patternForPlayback().elements; s.restart() }
        assertTrue(seen.size > 1)
    }

    @Test
    fun `stats record entry time, corrections and outcome`() {
        val elements = session.patternForPlayback().elements
        session.addElement(elements[0])
        session.addDash(); session.removeLast()
        now += 3_500
        elements.drop(1).forEach { session.addElement(it) }
        session.submit()
        val stats = session.stats()
        assertEquals(1, stats.submissions)
        assertEquals(0, stats.failures)
        assertEquals(1, stats.corrections)
        assertEquals(3_500L, stats.entryTimeMs)
        assertEquals(LocalState.AWAITING_APPROVAL, stats.outcome)
    }

    @Test
    fun `corrections are counted per round`() {
        session.addDot(); session.removeLast()
        assertEquals(1, session.stats().corrections)
        session.restart()
        assertEquals(0, session.stats().corrections)
        session.addDash(); session.removeLast()
        assertEquals(1, session.stats().corrections)
    }

    @Test
    fun `stats have no entry time when never matched`() {
        enterWrong(); session.submit()
        assertNull(session.stats().entryTimeMs)
    }

    @Test
    fun `toString does not reveal the pattern`() {
        val text = session.toString() + session.stats().toString()
        assertFalse(text.contains("DOT") || text.contains("DASH"))
        assertNotEquals("", text)
    }
}
